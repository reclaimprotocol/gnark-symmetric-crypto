package main

import (
	_ "embed"
	"gnark-symmetric-crypto/circuits"
)

// #include <stdlib.h>
import (
	"C"
)

func main() {}

//export Verify
func Verify(params []byte) bool {
	return circuits.Verify(params)
}
