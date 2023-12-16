package main

import "C"
import (
	"bytes"
	_ "embed"
	"fmt"
	"unsafe"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/reclaimprotocol/gnark-chacha20/chacha"
)

/* #include <stdlib.h>
   #include <stdint.h>
*/
import (
	"C"
)

func main() {}

//export Free
func Free(pointer unsafe.Pointer) {
	C.free(pointer)
}

//go:embed r1cs
var r1cs_embedded []byte

//go:embed pk
var pk_embedded []byte
var r1css constraint.ConstraintSystem
var pk groth16.ProvingKey

func init() {
	fmt.Println("about to read key & circuit")
	r1css = groth16.NewCS(ecc.BN254)
	_, err := r1css.ReadFrom(bytes.NewBuffer(r1cs_embedded))
	if err != nil {
		panic(err)
	}

	pk = groth16.NewProvingKey(ecc.BN254)
	_, err = pk.ReadFrom(bytes.NewBuffer(pk_embedded))
	if err != nil {
		panic(err)
	}
	fmt.Println("read key & circuit")
}

//export Prove
func Prove(key, nonce []byte, cnt C.int, plaintext, ciphertext []byte) (unsafe.Pointer, int) {
	witness := chacha.Circuit{}
	copy(witness.Key[:], chacha.BytesToUint32LE(key))
	copy(witness.Nonce[:], chacha.BytesToUint32LE(nonce))
	witness.Counter = uints.NewU32(uint32(cnt))
	copy(witness.In[:], chacha.BytesToUint32BE(plaintext))
	copy(witness.Out[:], chacha.BytesToUint32BE(ciphertext))
	wtns, err := frontend.NewWitness(&witness, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}
	gProof, err := groth16.Prove(r1css, pk, wtns)
	if err != nil {
		panic(err)
	}
	buf := &bytes.Buffer{}
	_, err = gProof.WriteTo(buf)
	if err != nil {
		panic(err)
	}
	res := buf.Bytes()
	return C.CBytes(res), len(res)
}
