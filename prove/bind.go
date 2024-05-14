package main

import "C"
import (
	"bytes"
	_ "embed"
	"unsafe"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/reclaimprotocol/gnark-chacha20/utils"
)

// #include <stdlib.h>
import (
	"C"
)

func main() {}

//export Free
func Free(pointer unsafe.Pointer) {
	C.free(pointer)
}

//go:embed r1cs
var r1csEmbedded []byte

//go:embed pk
var pkEmbedded []byte
var r1css constraint.ConstraintSystem
var pk groth16.ProvingKey

func init() {
	r1css = groth16.NewCS(ecc.BN254)
	_, err := r1css.ReadFrom(bytes.NewBuffer(r1csEmbedded))
	if err != nil {
		panic(err)
	}

	pk = groth16.NewProvingKey(ecc.BN254)
	_, err = pk.ReadFrom(bytes.NewBuffer(pkEmbedded))
	if err != nil {
		panic(err)
	}
	// log.Panicf("Init ok. Took %s\n", time.Since(t))
}

//export Init
func Init() {
	if len(r1csEmbedded) == 0 || len(pkEmbedded) == 0 {
		panic("could not load circuit and proving key")
	}
}

type Witness struct {
	Key     []uints.U32
	Counter uints.U32 `gnark:",public"`
	Nonce   []uints.U32
	In      []uints.U32 `gnark:",public"`
	Out     []uints.U32 `gnark:",public"`
}

func (c *Witness) Define(api frontend.API) error {
	return nil
}

//export Prove
func Prove(key []byte, nonce []byte, cnt C.int, plaintext, ciphertext []byte) (unsafe.Pointer, int) {
	uplaintext := utils.BytesToUint32BE(plaintext)
	uciphertext := utils.BytesToUint32BE(ciphertext)
	ukey := utils.BytesToUint32LE(key)
	unonce := utils.BytesToUint32LE(nonce)

	witness := Witness{
		Counter: uints.NewU32(0),
		Key:     make([]uints.U32, len(ukey)),
		Nonce:   make([]uints.U32, len(unonce)),
		In:      make([]uints.U32, len(uplaintext)),
		Out:     make([]uints.U32, len(uciphertext)),
	}
	copy(witness.Key[:], ukey)
	copy(witness.Nonce[:], unonce)
	witness.Counter = uints.NewU32(uint32(cnt))
	copy(witness.In[:], uplaintext)
	copy(witness.Out[:], uciphertext)
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
