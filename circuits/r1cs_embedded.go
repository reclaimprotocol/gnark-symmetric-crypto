//go:build !compiled

package circuits

import (
	"bytes"
	_ "embed"
	"fmt"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
)

//go:embed generated/r1cs.bits
var r1csChaChaEmbedded []byte

//go:embed generated/r1cs.aes128
var r1csAES128Embedded []byte

//go:embed generated/r1cs.aes256
var r1csAES256Embedded []byte

var circuits = map[string][]byte{
	"chacha20":    r1csChaChaEmbedded,
	"aes-128-ctr": r1csAES128Embedded,
	"aes-256-ctr": r1csAES256Embedded,
}

func GetR1CS(cipher string) constraint.ConstraintSystem {
	fmt.Printf("Using embedded R1CS %s\n", cipher)
	r1cs := groth16.NewCS(ecc.BN254)
	_, err := r1cs.ReadFrom(bytes.NewBuffer(circuits[cipher]))
	if err != nil {
		panic(err)
	}
	return r1cs
}
