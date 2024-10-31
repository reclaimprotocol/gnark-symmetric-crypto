package impl

import "C"
import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/logger"
)

type InputVerifyParams struct {
	Cipher        string  `json:"cipher"`
	Proof         []uint8 `json:"proof"`
	PublicSignals []uint8 `json:"publicSignals"`
}

type OPRFParams struct {
	Pos             uint32  `json:"pos"`
	Len             uint32  `json:"len"`
	DomainSeparator []uint8 `json:"domainSeparator"`
	PublicKey       []uint8 `json:"publicKey"`
	Output          []uint8 `json:"output"`

	NodeIndexes    []int     `json:"nodeIndexes"`
	NodePublicKeys [][]uint8 `json:"nodePublicKey"`
	NodeResponses  [][]uint8 `json:"nodeResponses"`
	C              [][]uint8 `json:"c"`
	R              [][]uint8 `json:"r"`
}
type InputChachaOPRFParams struct {
	Nonce   []uint8     `json:"nonce"`
	Counter uint32      `json:"counter"`
	Input   []uint8     `json:"input"` // ciphertext
	OPRF    *OPRFParams `json:"oprf"`
}

var verifiers = make(map[string]Verifier)

//go:embed generated/vk.chacha20
var vkChachaEmbedded []byte

//go:embed generated/vk.aes128
var vkAES128Embedded []byte

//go:embed generated/vk.aes256
var vkAES256Embedded []byte

//go:embed generated/vk.chacha20_oprf
var vkChachaOPRFEmbedded []byte

func init() {
	logger.Disable()

	vk := groth16.NewVerifyingKey(ecc.BN254)
	_, err := vk.ReadFrom(bytes.NewBuffer(vkChachaEmbedded))
	if err != nil {
		panic(err)
	}

	verifiers["chacha20"] = &ChachaVerifier{vk: vk}

	vk = groth16.NewVerifyingKey(ecc.BN254)
	_, err = vk.ReadFrom(bytes.NewBuffer(vkAES128Embedded))
	if err != nil {
		panic(err)
	}

	verifiers["aes-128-ctr"] = &AESVerifier{vk: vk}

	vk = groth16.NewVerifyingKey(ecc.BN254)
	_, err = vk.ReadFrom(bytes.NewBuffer(vkAES256Embedded))
	if err != nil {
		panic(err)
	}

	verifiers["aes-256-ctr"] = &AESVerifier{vk: vk}

	vk = groth16.NewVerifyingKey(ecc.BN254)
	_, err = vk.ReadFrom(bytes.NewBuffer(vkChachaOPRFEmbedded))
	if err != nil {
		panic(err)
	}

	verifiers["chacha20-oprf"] = &ChachaOPRFVerifier{vk: vk}
}

func Verify(params []byte) (res bool) {

	defer func() {
		if err := recover(); err != nil {
			fmt.Println(err)
			res = false
		}
	}()

	var inputParams *InputVerifyParams
	err := json.Unmarshal(params, &inputParams)
	if err != nil {
		fmt.Println(err)
		return false
	}

	if verifier, ok := verifiers[inputParams.Cipher]; ok {
		return verifier.Verify(inputParams.Proof, inputParams.PublicSignals)
	}
	return false
}
