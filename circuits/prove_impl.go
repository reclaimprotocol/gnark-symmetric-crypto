package circuits

import (
	"bytes"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"unsafe"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/rs/zerolog"
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

type Proof struct {
	ProofJson string `json:"proofJson"`
}

type OutputParams struct {
	Proof         Proof `json:"proof"`
	PublicSignals []int `json:"publicSignals"`
}

type ProverParams struct {
	Prover
	wg   *sync.WaitGroup
	Init func()
}

var initChaCha sync.WaitGroup
var initAES128 sync.WaitGroup
var initAES256 sync.WaitGroup

var a, b, c bool

//go:embed generated/pk.bits
var pkChaChaEmbedded []byte

//go:embed generated/r1cs.bits
var r1csChaChaEmbedded []byte

//go:embed generated/pk.aes128
var pkAES128Embedded []byte

//go:embed generated/r1cs.aes128
var r1csAES128Embedded []byte

//go:embed generated/pk.aes256
var pkAES256Embedded []byte

//go:embed generated/r1cs.aes256
var r1csAES256Embedded []byte

var InitChaChaFunc = sync.OnceFunc(func() {
	fmt.Println("loading ChaCha20")
	defer initChaCha.Done()
	r1csChaCha := groth16.NewCS(ecc.BN254)
	_, err := r1csChaCha.ReadFrom(bytes.NewBuffer(r1csChaChaEmbedded))
	if err != nil {
		panic(err)
	}
	pkChaCha := groth16.NewProvingKey(ecc.BN254)
	_, err = pkChaCha.ReadFrom(bytes.NewBuffer(pkChaChaEmbedded))
	if err != nil {
		panic(err)
	}
	provers["chacha20"].Prover = &ChaChaProver{
		r1cs: r1csChaCha,
		pk:   pkChaCha,
	}
	a = true
})

var InitAES128Func = sync.OnceFunc(func() {
	fmt.Println("loading AES128")
	defer initAES128.Done()

	r1csAES128 := groth16.NewCS(ecc.BN254)
	_, err := r1csAES128.ReadFrom(bytes.NewBuffer(r1csAES128Embedded))
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
	b = true
})

var InitAES256Func = sync.OnceFunc(func() {
	fmt.Println("loading AES256")
	defer initAES256.Done()

	r1csAES256 := groth16.NewCS(ecc.BN254)
	_, err := r1csAES256.ReadFrom(bytes.NewBuffer(r1csAES256Embedded))
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
	c = true
})

var provers = map[string]*ProverParams{
	"chacha20":    {wg: &initChaCha},
	"aes-128-ctr": {wg: &initAES128},
	"aes-256-ctr": {wg: &initAES256},
}

func init() {
	zerolog.SetGlobalLevel(zerolog.Disabled)
	initChaCha.Add(1)
	initAES128.Add(1)
	initAES256.Add(1)
	provers["chacha20"].Init = InitChaChaFunc
	provers["aes-128-ctr"].Init = InitAES128Func
	provers["aes-256-ctr"].Init = InitAES256Func
}

func initDone() bool {
	return a && b && c
}

var InitFunc = sync.OnceFunc(func() {
	go InitChaChaFunc()
	go InitAES128Func()
	go InitAES256Func()
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

	var cipherParams *InputParamsCipher
	err := json.Unmarshal(params, &cipherParams)
	if err != nil {
		panic(err)
	}
	if prover, ok := provers[cipherParams.Cipher]; ok {
		go prover.Init()
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
				Proof: Proof{
					ProofJson: hex.EncodeToString(proof),
				},
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
					Proof: Proof{
						ProofJson: hex.EncodeToString(proof),
					},
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
