package impl

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"runtime"
	"unsafe"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/rs/zerolog"
)

// #include <stdlib.h>
import (
	"C"
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
		KeyHash:     "5c4053dc1a731b5dcd059ca9e1753b018f8713ff4838504a2232f2d4cf5e0526",
		CircuitHash: "b849a7b157921280e73f28716a097acc524b43ac133a98d8bb434c1072118f02",
		Prover:      &AESProver{},
	},
	"aes-256-ctr": {
		KeyHash:     "0c0c06a3dbfe1f155a8b191b0d6ea081aae6e74cd77de3acc1d487094b3cab31",
		CircuitHash: "9fc93c79c0656e95f1f6d573380edba22e07c9a97e2d876d86115cb04a5cf4cd",
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
		runtime.GC()
	}()

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
		return C.CBytes(res), len(res)

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
