package main

import (
	"gnark-symmetric-crypto/libraries/prover/impl"
	"unsafe"
)

// #include <stdlib.h>
import (
	"C"
)

func main() {}

//export enforce_binding
func enforce_binding() {}

//export InitAlgorithm
func InitAlgorithm(algorithmID uint8, provingKey []byte, r1cs []byte) bool {
	return impl.InitAlgorithm(algorithmID, provingKey, r1cs)
}

//export Free
func Free(pointer unsafe.Pointer) {
	C.free(pointer)
}

//export Prove
func Prove(params []byte) (unsafe.Pointer, int) {
	return impl.Prove(params)
}
