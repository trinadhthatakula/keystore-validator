package main

import (
	"encoding/binary"
	"testing"
)

func TestDecodeModifiedUTF8(t *testing.T) {
	cases := []struct {
		input []byte
		want  string
		valid bool
	}{
		{[]byte("hello"), "hello", true},
		{[]byte{0xc0, 0x80}, "\x00", true},
		{[]byte{0xc3, 0xa9}, "é", true},
		{[]byte{0xed, 0xa0, 0xbd, 0xed, 0xb8, 0x80}, "😀", true},
		{[]byte{0xed, 0xa0, 0xbd}, "", false},
		{[]byte{0, 0}, "", false},
		{[]byte{0xc1, 0x81}, "", false},
		{[]byte{0xf0, 0x9f, 0x98, 0x80}, "", false},
	}
	for _, c := range cases {
		got, err := decodeModifiedUTF8(c.input)
		if (err == nil) != c.valid || (c.valid && got != c.want) {
			t.Errorf("decode %x = %q, %v, want %q valid=%v", c.input, got, err, c.want, c.valid)
		}
	}
}

func TestPreflightRejectsHostileLengthsAndCounts(t *testing.T) {
	data := make([]byte, 32)
	binary.BigEndian.PutUint32(data[0:4], 0xfeedfeed)
	binary.BigEndian.PutUint32(data[4:8], 2)
	binary.BigEndian.PutUint32(data[8:12], 0xffffffff)
	if _, err := preflight(data); err == nil {
		t.Fatal("accepted impossible entry count")
	}
	if r := Inspect(data, "password"); r.OK || r.Error.Code != "INVALID_JKS" {
		t.Fatalf("got %#v", r)
	}
}

func TestErrorLabels(t *testing.T) {
	if r := Inspect([]byte("bad"), "x"); r.OK || r.Error.Code != "UNSUPPORTED_FORMAT" {
		t.Fatalf("got %#v", r)
	}
	if r := Inspect(make([]byte, maxStoreBytes+1), "x"); r.OK || r.Error.Code != "FILE_TOO_LARGE" {
		t.Fatalf("got %#v", r)
	}
}
