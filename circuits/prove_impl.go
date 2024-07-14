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

type InputParamsCipher struct {
	Cipher string `json:"cipher"`
}

type InputParamsChaCha struct {
	Cipher  string    `json:"cipher"`
	Key     [][]uint8 `json:"key"`
	Nonce   [][]uint8 `json:"nonce"`
	Counter []uint8   `json:"counter"`
	Input   [][]uint8 `json:"input"`
}

type InputParamsAES struct {
	Cipher  string  `json:"cipher"`
	Key     []uint8 `json:"key"`
	Nonce   []uint8 `json:"nonce"`
	Counter []uint8 `json:"counter"`
	Input   []uint8 `json:"input"`
}

type OutputParams struct {
	ProofJson     string `json:"proofJson"`
	PublicSignals []int  `json:"publicSignals"`
}

type ProverParams struct {
	Prover
	wg *sync.WaitGroup
}

var initChaCha sync.WaitGroup
var initAES128 sync.WaitGroup
var initAES256 sync.WaitGroup

var provers = map[string]*ProverParams{
	"chacha20":    {wg: &initChaCha},
	"aes-128-ctr": {wg: &initAES128},
	"aes-256-ctr": {wg: &initAES256},
}

//go:embed generated/pk.bits
var pkChaChaEmbedded []byte
var ChachaDone bool

//go:embed generated/pk.aes128
var pkAES128Embedded []byte

//go:embed generated/pk.aes256
var pkAES256Embedded []byte

func init() {
	initChaCha.Add(1)
	initAES128.Add(1)
	initAES256.Add(1)
}

var InitFunc = sync.OnceFunc(func() {
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

	provers["chacha20"].Prover = &ChaChaProver{
		r1cs: r1cssChaCha,
		pk:   pkChaCha,
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

	provers["aes-128-ctr"].Prover = &AESProver{
		r1cs: r1csAES128,
		pk:   pkAES128,
	}
	initAES128.Done()

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

	provers["aes-256-ctr"].Prover = &AESProver{
		r1cs: r1csAES256,
		pk:   pkAES256,
	}

	initAES256.Done()
	fmt.Println("Done compiling")

})

func Prove(params []byte) (proofRes unsafe.Pointer, resLen int) {

	defer func() {
		if err := recover(); err != nil {
			fmt.Println(err)
			bRes, er := json.Marshal(err)
			if er != nil {
				fmt.Println(er)
			}
			proofRes, resLen = C.CBytes(bRes), len(bRes)
		}
	}()

	go InitFunc() // in case it wasn't called before
	var cipherParams *InputParamsCipher
	err := json.Unmarshal(params, &cipherParams)
	if err != nil {
		panic(err)
	}
	if prover, ok := provers[cipherParams.Cipher]; ok {
		prover.wg.Wait()

		if cipherParams.Cipher == "chacha20" {
			var inputParams *InputParamsChaCha
			err = json.Unmarshal(params, &inputParams)
			if err != nil {
				panic(err)
			}

			proof, ciphertext := prover.ProveChaCha(inputParams.Key, inputParams.Nonce, inputParams.Counter, inputParams.Input)

			ct := make([]int, 0, len(ciphertext))
			for i := 0; i < len(ciphertext); i++ {
				ct = append(ct, int(ciphertext[i]))
			}

			res, er := json.Marshal(&OutputParams{
				ProofJson:     hex.EncodeToString(proof),
				PublicSignals: ct,
			})
			if er != nil {
				panic(er)
			}
			return C.CBytes(res), len(res)
		} else {
			{
				var inputParams *InputParamsAES
				err = json.Unmarshal(params, &inputParams)
				if err != nil {
					panic(err)
				}

				proof, ciphertext := prover.ProveAES(inputParams.Key, inputParams.Nonce, inputParams.Counter, inputParams.Input)
				ct := make([]int, 0, len(ciphertext))
				for i := 0; i < len(ciphertext); i++ {
					ct = append(ct, int(ciphertext[i]))
				}
				res, er := json.Marshal(&OutputParams{
					ProofJson:     hex.EncodeToString(proof),
					PublicSignals: ct,
				})
				if er != nil {
					panic(er)
				}
				return C.CBytes(res), len(res)
			}
		}

	} else {
		panic("could not find prover " + cipherParams.Cipher)
	}
}
