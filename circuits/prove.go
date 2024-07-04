package circuits

import (
	"bytes"
	_ "embed"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"gnark-symmetric-crypto/circuits/aes"
	"gnark-symmetric-crypto/circuits/chachaV3"
	"sync"
	"unsafe"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

// #include <stdlib.h>
import (
	"C"
)

type InputParams struct {
	Name      string `json:"name"`
	Key       string `json:"key"`
	Nonce     string `json:"nonce"`
	Counter   uint32 `json:"counter"`
	Plaintext string `json:"plaintext"`
}

type OutputParams struct {
	Proof      string `json:"proof"`
	Ciphertext string `json:"ciphertext"`
}

type ProverParams struct {
	Prover
	R1CS constraint.ConstraintSystem
	pk   groth16.ProvingKey
	wg   *sync.WaitGroup
}

var provers map[string]ProverParams

//go:embed pk
var pkChaChaEmbedded []byte
var r1cssChaCha constraint.ConstraintSystem
var pkChaCha groth16.ProvingKey
var ChachaDone bool

//go:embed pk.aes128
var pkAES128Embedded []byte
var r1cssAES128 constraint.ConstraintSystem
var pkAES128 groth16.ProvingKey
var AES128Done bool

//go:embed pk.aes256
var pkAES256Embedded []byte
var r1cssAES256 constraint.ConstraintSystem
var pkAES256 groth16.ProvingKey
var AES256Done bool

var initChaCha sync.WaitGroup
var initAES128 sync.WaitGroup
var initAES256 sync.WaitGroup

func init() {
	initChaCha.Add(1)
	initAES128.Add(1)
	initAES256.Add(1)
}

var InitFunc = sync.OnceFunc(func() {

	if len(pkChaChaEmbedded) == 0 ||
		len(pkAES128Embedded) == 0 ||
		len(pkAES256Embedded) == 0 {
		panic("could not load circuit and proving key")
	}

	fmt.Println("compiling ChaCha20")
	var err error

	curve := ecc.BN254.ScalarField()

	witnessChaCha := chachaV3.ChaChaCircuit{}
	r1cssChaCha, err = frontend.Compile(curve, r1cs.NewBuilder, &witnessChaCha, frontend.WithCapacity(25000))
	if err != nil {
		panic(err)
	}
	pkChaCha = groth16.NewProvingKey(ecc.BN254)
	_, err = pkChaCha.ReadFrom(bytes.NewBuffer(pkChaChaEmbedded))
	if err != nil {
		panic(err)
	}
	initChaCha.Done()
	ChachaDone = true

	fmt.Println("compiling AES128")
	witnessAES128 := aes.AES128Wrapper{
		Key:        [16]frontend.Variable{},
		Plaintext:  [16]frontend.Variable{},
		Ciphertext: [16]frontend.Variable{},
	}
	r1cssAES128, err = frontend.Compile(curve, r1cs.NewBuilder, &witnessAES128, frontend.WithCapacity(150000))

	if err != nil {
		panic(err)
	}

	pkAES128 = groth16.NewProvingKey(ecc.BN254)
	_, err = pkAES128.ReadFrom(bytes.NewBuffer(pkAES128Embedded))
	if err != nil {
		panic(err)
	}
	initAES128.Done()
	AES128Done = true

	fmt.Println("compiling AES256")
	witnessAES256 := aes.AES256Wrapper{
		Key:        [32]frontend.Variable{},
		Plaintext:  [16]frontend.Variable{},
		Ciphertext: [16]frontend.Variable{},
	}
	r1cssAES256, err = frontend.Compile(curve, r1cs.NewBuilder, &witnessAES256, frontend.WithCapacity(200000))
	if err != nil {
		panic(err)
	}
	pkAES256 = groth16.NewProvingKey(ecc.BN254)
	_, err = pkAES256.ReadFrom(bytes.NewBuffer(pkAES256Embedded))
	if err != nil {
		panic(err)
	}
	initAES256.Done()
	AES256Done = true
	fmt.Println("Done compiling")
	provers = map[string]ProverParams{
		"chacha20": {
			Prover: &ChaChaProver{},
			R1CS:   r1cssChaCha,
			pk:     pkChaCha,
			wg:     &initChaCha,
		},
		"aes-128-ctr": {
			Prover: &AES128Prover{},
			R1CS:   r1cssAES128,
			pk:     pkAES128,
			wg:     &initAES128,
		},
		"aes-256-ctr": {
			Prover: &AES256Prover{},
			R1CS:   r1cssAES256,
			pk:     pkAES256,
			wg:     &initAES256,
		},
	}
})

func Prove(params []byte) (unsafe.Pointer, int) {
	var inputParams *InputParams
	err := json.Unmarshal(params, &inputParams)
	if err != nil {
		panic(err)
	}
	if prover, ok := provers[inputParams.Name]; ok {
		prover.wg.Wait()

		counter := binary.BigEndian.AppendUint32(nil, inputParams.Counter)

		proof, ciphertext := prover.Prove(prover.R1CS, prover.pk, counter, mustHex(inputParams.Key), mustHex(inputParams.Nonce), mustHex(inputParams.Plaintext))
		res, er := json.Marshal(&OutputParams{
			Proof:      hex.EncodeToString(proof),
			Ciphertext: hex.EncodeToString(ciphertext),
		})
		if er != nil {
			panic(er)
		}
		return C.CBytes(res), len(res)
	} else {
		panic("could not find prover " + inputParams.Name)
	}
}

func mustHex(s string) []byte {
	res, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return res
}
