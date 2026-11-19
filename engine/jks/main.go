//go:build js && wasm

package main

import (
	"encoding/json"
	"syscall/js"
)

func resultValue(r inspectResult) interface{} {
	// Marshal and parse to correctly map nested structs and slices to JS objects.
	encoded, _ := json.Marshal(r)
	return js.Global().Get("JSON").Call("parse", string(encoded))
}

func main() {
	inspect := js.FuncOf(func(this js.Value, args []js.Value) (result interface{}) {
		defer func() {
			if recover() != nil {
				result = resultValue(failure("INSPECTION_ERROR", "The keystore could not be read."))
			}
		}()
		if len(args) != 2 || args[0].Type() != js.TypeObject || !args[0].InstanceOf(js.Global().Get("Uint8Array")) || args[1].Type() != js.TypeString {
			return resultValue(failure("INVALID_INPUT", "Select a keystore and enter its store password."))
		}
		length := args[0].Length()
		if length > maxStoreBytes {
			return resultValue(failure("FILE_TOO_LARGE", "Keystores larger than 16 MiB are not supported."))
		}
		data := make([]byte, length)
		js.CopyBytesToGo(data, args[0])
		defer clear(data)
		return resultValue(Inspect(data, args[1].String()))
	})
	js.Global().Set("inspectJks", inspect)
	select {}
}
