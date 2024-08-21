package impl

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"runtime"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/rs/zerolog"
)

const (
	CHACHA20 = 0
	AES_128  = 1
	AES_256  = 2
)

var algorithmNames = map[uint8]string{
	CHACHA20: "chacha20",
	AES_128:  "aes-128-ctr",
	AES_256:  "aes-256-ctr",
}

var provers = map[string]*ProverParams{
	"chacha20": {
		KeyHash:     "500d19eeccee0b3749e369c1839a1de0183dc7e8e43c4f9ad36e9c4b6537f03e",
		CircuitHash: "1ee90d87e5262923f0db0efe473a368a9c4bebdea0ddebe196e2d8363a538502",
		Prover:      &ChaChaProver{},
	},
	"aes-128-ctr": {
		KeyHash:     "9dea83ebb87923ccb0870a75bc21c341498d2df396a76e6f54eafb4cc331d9e0",
		CircuitHash: "f51412818e9df3d556c8de879e637bcaf65c41a79d677aa1a81be4df779ddb60",
		Prover:      &AESProver{},
	},
	"aes-256-ctr": {
		KeyHash:     "069a556d171c434fd957dc07262c771f8cd34c300142844344a5b32a6e7873aa",
		CircuitHash: "f8a27dc46c40748052d0efcd90dbc38ec82a92e7dad99f3874dc65330c806fa6",
		Prover:      &AESProver{},
	},
}

type InputParamsCipher struct {
	Cipher string `json:"cipher"`
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
	KeyHash     string
	CircuitHash string
	initDone    bool
}

func init() {
	zerolog.SetGlobalLevel(zerolog.Disabled)
}

func InitAlgorithm(algorithmID uint8, provingKey []byte, r1csData []byte) (res bool) {
	defer func() {
		if err := recover(); err != nil {
			fmt.Println(err)
			res = false
		}
	}()
	if alg, ok := algorithmNames[algorithmID]; ok {
		proverParams := provers[alg]
		if proverParams.initDone {
			return true
		}

		inHash := sha256.Sum256(provingKey)
		keyHash := mustHex(proverParams.KeyHash)

		if subtle.ConstantTimeCompare(inHash[:], keyHash) != 1 {
			fmt.Println("incorrect hash")
			return false
		}

		pkey := groth16.NewProvingKey(ecc.BN254)
		_, err := pkey.ReadFrom(bytes.NewBuffer(provingKey))
		if err != nil {
			fmt.Println(fmt.Errorf("error reading proving key: %v", err))
			return false
		}

		var r1cs constraint.ConstraintSystem
		if len(r1csData) > 0 {
			r1cs = groth16.NewCS(ecc.BN254)
			_, err = r1cs.ReadFrom(bytes.NewBuffer(r1csData))
			if err != nil {
				fmt.Println(fmt.Errorf("error reading r1cs: %v", err))
				return false
			}

			inHash = sha256.Sum256(r1csData)
			circuitHash := mustHex(proverParams.CircuitHash)

			if subtle.ConstantTimeCompare(inHash[:], circuitHash) != 1 {
				fmt.Println(fmt.Errorf("circuit hash mismatch"))
				return false
			}
		} else {
			r1cs = GetR1CS(alg)
		}

		proverParams.SetParams(r1cs, pkey)
		proverParams.initDone = true
		return true
	}
	return false
}

func Prove(params []byte) []byte {
	defer runtime.GC()
	var cipherParams *InputParamsCipher
	err := json.Unmarshal(params, &cipherParams)
	if err != nil {
		panic(err)
	}
	if prover, ok := provers[cipherParams.Cipher]; ok {

		if !prover.initDone {
			panic(fmt.Sprintf("proving params are not initialized for cipher: %s", cipherParams.Cipher))
		}
		proof, ciphertext := prover.Prove(params)

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
		return res

	} else {
		panic("could not find prover " + cipherParams.Cipher)
	}
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}
