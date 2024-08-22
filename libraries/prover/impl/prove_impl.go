package impl

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"

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
		KeyHash:     "78c14595e60e2054cbcee1c465d3863d166d3c667ef2743d9e7f18afee2b3629",
		CircuitHash: "1ee90d87e5262923f0db0efe473a368a9c4bebdea0ddebe196e2d8363a538502",
		Prover:      &ChaChaProver{},
	},
	"aes-128-ctr": {
		KeyHash:     "2cd331f090336cf3a3bca4448749882a755d717b2611c80d61874f531b87bce6",
		CircuitHash: "0a4cbc377a275b68842a85151853187dd3047b58611df5f95bcfe88d696c71e4",
		Prover:      &AESProver{},
	},
	"aes-256-ctr": {
		KeyHash:     "43b285c33f4f0b6ef0e002618f1acdc2a45fcc893d3a91a5470a9d4117bab207",
		CircuitHash: "956737c28a6964aa9444107329cf26a575bebc09e4e2a0d6b355ccc5e87afc91",
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
