//go:build !download_circuits

package impl

import (
	"fmt"
	"gnark-symmetric-crypto/circuits/aes"
	"gnark-symmetric-crypto/circuits/chachaV3"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

type R1CSCompiler interface {
	GetR1CS() constraint.ConstraintSystem
}

type ChaCha20R1CSCompiler struct{}

func (_ *ChaCha20R1CSCompiler) GetR1CS() constraint.ConstraintSystem {
	curve := ecc.BN254.ScalarField()
	witnessChaCha := chachaV3.ChaChaCircuit{}
	r1csChaCha, err := frontend.Compile(curve, r1cs.NewBuilder, &witnessChaCha, frontend.WithCapacity(25000))
	if err != nil {
		panic(err)
	}
	return r1csChaCha
}

type AES128R1CSCompiler struct{}

func (_ *AES128R1CSCompiler) GetR1CS() constraint.ConstraintSystem {
	curve := ecc.BN254.ScalarField()
	witnessAES128 := aes.AES128Wrapper{
		AESWrapper: aes.AESWrapper{
			Key: make([]frontend.Variable, 16),
		},
	}
	r1csAES128, err := frontend.Compile(curve, r1cs.NewBuilder, &witnessAES128)
	if err != nil {
		panic(err)
	}
	return r1csAES128
}

type AES256R1CSCompiler struct{}

func (_ *AES256R1CSCompiler) GetR1CS() constraint.ConstraintSystem {
	curve := ecc.BN254.ScalarField()
	witnessAES256 := aes.AES256Wrapper{
		AESWrapper: aes.AESWrapper{
			Key: make([]frontend.Variable, 32),
		},
	}
	r1csAES256, err := frontend.Compile(curve, r1cs.NewBuilder, &witnessAES256, frontend.WithCapacity(200000))
	if err != nil {
		panic(err)
	}
	return r1csAES256
}

var circuitCompilers = map[string]R1CSCompiler{
	"chacha20":    &ChaCha20R1CSCompiler{},
	"aes-128-ctr": &AES128R1CSCompiler{},
	"aes-256-ctr": &AES256R1CSCompiler{},
}

func GetR1CS(cipher string) constraint.ConstraintSystem {
	fmt.Printf("Compiling circuit for %s\n", cipher)
	compiler := circuitCompilers[cipher]
	if compiler == nil {
		panic("unknown compiler")
	}
	return compiler.GetR1CS()
}
