package main

import (
	"gnark-symmetric-crypto/circuits"
	"unsafe"
)

// #include <stdlib.h>
import (
	"C"
)

func main() {}

//export enforce_binding
func enforce_binding() {}

//export Init
func Init() {
	go circuits.InitFunc()
}

//export InitComplete
func InitComplete() bool {
	return circuits.ChachaDone && circuits.AES128Done && circuits.AES256Done
}

//export Free
func Free(pointer unsafe.Pointer) {
	C.free(pointer)
}

//export Prove
func Prove(params []byte) (unsafe.Pointer, int) {
	return circuits.Prove(params)
}
