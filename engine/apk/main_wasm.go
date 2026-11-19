//go:build js && wasm

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"syscall/js"

	"github.com/agusibrahim/apksig-go/pkg/datasource"
)

// fileSource reads bounded slices synchronously inside a Web Worker. It never
// transfers the entire File into WASM memory. FileReaderSync is worker-only.
type fileSource struct {
	file      js.Value
	reader    js.Value
	off, size int64
}

func (s *fileSource) Size() int64 { return s.size }
func (s *fileSource) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 || off > s.size {
		return 0, fmt.Errorf("APK read out of bounds")
	}
	available := s.size - off
	n := len(p)
	if int64(n) > available {
		n = int(available)
	}
	if n > 0 {
		fragment := s.file.Call("slice", float64(s.off+off), float64(s.off+off+int64(n)))
		raw := s.reader.Call("readAsArrayBuffer", fragment)
		copied := js.CopyBytesToGo(p[:n], js.Global().Get("Uint8Array").New(raw))
		if copied != n {
			return copied, io.ErrUnexpectedEOF
		}
	}
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}
func (s *fileSource) Slice(off, length int64) datasource.DataSource {
	if off < 0 || length < 0 || off > s.size || length > s.size-off {
		panic("APK slice out of bounds")
	}
	return &fileSource{file: s.file, reader: s.reader, off: s.off + off, size: length}
}
func jsResult(r result) js.Value {
	b, err := json.Marshal(r)
	if err != nil {
		return js.Null()
	}
	return js.Global().Get("JSON").Call("parse", string(b))
}
func jsVerify(_ js.Value, args []js.Value) (out any) {
	defer func() {
		if recover() != nil {
			r := emptyResult()
			out = jsResult(fail(r, "The APK is malformed or could not be read safely."))
		}
	}()
	r := emptyResult()
	if len(args) != 1 || args[0].Type() != js.TypeObject || args[0].Get("slice").Type() != js.TypeFunction || args[0].Get("size").Type() != js.TypeNumber {
		return jsResult(fail(r, "Select an APK file."))
	}
	file := args[0]
	size := file.Get("size").Float()
	if size < 0 || size > float64(maxAPKSize) {
		return jsResult(fail(r, "APK exceeds the 1 GiB safety limit."))
	}
	constructor := js.Global().Get("FileReaderSync")
	if constructor.Type() != js.TypeFunction {
		return jsResult(fail(r, "This browser cannot read files in a worker."))
	}
	ds := &fileSource{file: file, reader: constructor.New(), size: int64(size)}
	return jsResult(verifyAPK(ds))
}
func main() {
	js.Global().Set("keystoreVerifyApk", js.FuncOf(jsVerify))
	select {}
}
