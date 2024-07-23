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
	// lazy loading means no need to wait
	return true
}

//export Free
func Free(pointer unsafe.Pointer) {
	C.free(pointer)
}

//export Prove
func Prove(params []byte) (unsafe.Pointer, int) {
	return circuits.Prove(params)
}
