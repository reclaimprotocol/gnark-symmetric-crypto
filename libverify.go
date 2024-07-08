package main

import (
	"gnark-symmetric-crypto/verifier"
)

// #include <stdlib.h>
import (
	"C"
)

func main() {}

//export Verify
func Verify(params []byte) bool {
	return verifier.Verify(params)
}
