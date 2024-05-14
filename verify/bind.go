package main

import "C"
import (
	"bytes"
	_ "embed"
	"fmt"

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

//go:embed r1cs
var r1csEmbedded []byte

//go:embed vk
var vkEmbedded []byte
var r1css constraint.ConstraintSystem
var vk groth16.VerifyingKey

func init() {
	r1css = groth16.NewCS(ecc.BN254)
	_, err := r1css.ReadFrom(bytes.NewBuffer(r1csEmbedded))
	if err != nil {
		panic(err)
	}

	vk = groth16.NewVerifyingKey(ecc.BN254)
	_, err = vk.ReadFrom(bytes.NewBuffer(vkEmbedded))
	if err != nil {
		panic(err)
	}
}

//export Init
func Init() {
	if r1css == nil || vk == nil {
		panic("could not load circuit and proving key")
	}
}

type Witness struct {
	Counter uints.U32   `gnark:",public"`
	In      []uints.U32 `gnark:",public"`
	Out     []uints.U32 `gnark:",public"`
}

func (c *Witness) Define(_ frontend.API) error {
	return nil
}

//export Verify
func Verify(proof []byte, cnt C.int, plaintext, ciphertext []byte) bool {
	uplaintext := utils.BytesToUint32BE(plaintext)
	uciphertext := utils.BytesToUint32BE(ciphertext)

	witness := Witness{
		Counter: uints.NewU32(uint32(cnt)),
		In:      make([]uints.U32, len(uplaintext)),
		Out:     make([]uints.U32, len(uciphertext)),
	}
	copy(witness.In[:], uplaintext)
	copy(witness.Out[:], uciphertext)
	wtns, err := frontend.NewWitness(&witness, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		panic(err)
	}

	gProof := groth16.NewProof(ecc.BN254)
	_, err = gProof.ReadFrom(bytes.NewBuffer(proof))
	if err != nil {
		panic(err)
	}
	err = groth16.Verify(gProof, vk, wtns)
	fmt.Println(err)
	return err == nil
}
