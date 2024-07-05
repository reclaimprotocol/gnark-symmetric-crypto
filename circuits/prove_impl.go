package circuits

import (
	"bytes"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"gnark-symmetric-crypto/circuits/aes"
	"gnark-symmetric-crypto/circuits/chachaV3"
	"sync"
	"unsafe"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

// #include <stdlib.h>
import (
	"C"
)

type InputParams struct {
	Cipher  string `json:"cipher"`
	Key     string `json:"key"`
	Nonce   string `json:"nonce"`
	Counter uint32 `json:"counter"`
	Input   string `json:"input"`
}

type OutputParams struct {
	Proof  string `json:"proof"`
	Output string `json:"output"`
}

type ProverParams struct {
	Prover
	wg *sync.WaitGroup
}

var provers map[string]*ProverParams

//go:embed generated/pk.bits
var pkChaChaEmbedded []byte
var ChachaDone bool

//go:embed generated/pk.aes128
var pkAES128Embedded []byte
var AES128Done bool

//go:embed generated/pk.aes256
var pkAES256Embedded []byte
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
	provers = make(map[string]*ProverParams)

	fmt.Println("compiling ChaCha20")
	var err error

	curve := ecc.BN254.ScalarField()

	witnessChaCha := chachaV3.ChaChaCircuit{}
	r1cssChaCha, err := frontend.Compile(curve, r1cs.NewBuilder, &witnessChaCha, frontend.WithCapacity(25000))
	if err != nil {
		panic(err)
	}
	pkChaCha := groth16.NewProvingKey(ecc.BN254)
	_, err = pkChaCha.ReadFrom(bytes.NewBuffer(pkChaChaEmbedded))
	if err != nil {
		panic(err)
	}

	provers["chacha20"] = &ProverParams{
		Prover: &ChaChaProver{
			r1cs: r1cssChaCha,
			pk:   pkChaCha,
		},
		wg: &initChaCha,
	}

	initChaCha.Done()
	ChachaDone = true

	fmt.Println("compiling AES128")
	witnessAES128 := aes.AES128Wrapper{
		AESWrapper: aes.AESWrapper{
			Key: make([]frontend.Variable, 16),
		},
	}
	r1csAES128, err := frontend.Compile(curve, r1cs.NewBuilder, &witnessAES128, frontend.WithCapacity(150000))

	if err != nil {
		panic(err)
	}

	pkAES128 := groth16.NewProvingKey(ecc.BN254)
	_, err = pkAES128.ReadFrom(bytes.NewBuffer(pkAES128Embedded))
	if err != nil {
		panic(err)
	}

	provers["aes-128-ctr"] = &ProverParams{
		Prover: &AESProver{
			r1cs: r1csAES128,
			pk:   pkAES128,
		},
		wg: &initAES128,
	}

	initAES128.Done()
	AES128Done = true

	fmt.Println("compiling AES256")
	witnessAES256 := aes.AES256Wrapper{
		AESWrapper: aes.AESWrapper{
			Key: make([]frontend.Variable, 32),
		},
	}
	r1csAES256, err := frontend.Compile(curve, r1cs.NewBuilder, &witnessAES256, frontend.WithCapacity(200000))
	if err != nil {
		panic(err)
	}
	pkAES256 := groth16.NewProvingKey(ecc.BN254)
	_, err = pkAES256.ReadFrom(bytes.NewBuffer(pkAES256Embedded))
	if err != nil {
		panic(err)
	}

	provers["aes-256-ctr"] = &ProverParams{
		Prover: &AESProver{
			r1cs: r1csAES256,
			pk:   pkAES256,
		},
		wg: &initAES256,
	}

	initAES256.Done()
	AES256Done = true
	fmt.Println("Done compiling")

})

func Prove(params []byte) (unsafe.Pointer, int) {
	var inputParams *InputParams
	err := json.Unmarshal(params, &inputParams)
	if err != nil {
		panic(err)
	}
	if prover, ok := provers[inputParams.Cipher]; ok {
		prover.wg.Wait()
		proof, ciphertext := prover.Prove(mustHex(inputParams.Key), mustHex(inputParams.Nonce), inputParams.Counter, mustHex(inputParams.Input))
		res, er := json.Marshal(&OutputParams{
			Proof:  hex.EncodeToString(proof),
			Output: hex.EncodeToString(ciphertext),
		})
		if er != nil {
			panic(er)
		}
		return C.CBytes(res), len(res)
	} else {
		panic("could not find prover " + inputParams.Cipher)
	}
}

func mustHex(s string) []byte {
	res, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return res
}
