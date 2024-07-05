package circuits

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"gnark-symmetric-crypto/circuits/aes"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/rs/zerolog/log"
)

type InputVerifyParams struct {
	Cipher string `json:"cipher"`
	Proof  string `json:"proof"`
	Input  string `json:"input"`
	Output string `json:"output"`
}

var verifiers = make(map[string]Verifier)

//go:embed generated/vk.bits
var vkChachaEmbedded []byte

//go:embed generated/vk.aes128
var vkAES128Embedded []byte

//go:embed generated/vk.aes256
var vkAES256Embedded []byte

func init() {

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

	verifiers["aes-128-ctr"] = &AESVerifier{
		vk: vk,
		wrapMaker: func(input, output []byte) frontend.Circuit {
			circuit := &aes.AES128Wrapper{
				AESWrapper: aes.AESWrapper{Key: make([]frontend.Variable, 16)},
			}

			for i := 0; i < len(input); i++ {
				circuit.Plaintext[i] = input[i]
			}

			for i := 0; i < len(output); i++ {
				circuit.Ciphertext[i] = output[i]
			}
			return circuit
		},
	}

	vk = groth16.NewVerifyingKey(ecc.BN254)
	_, err = vk.ReadFrom(bytes.NewBuffer(vkAES256Embedded))
	if err != nil {
		panic(err)
	}

	verifiers["aes-256-ctr"] = &AESVerifier{
		vk: vk,
		wrapMaker: func(input, output []byte) frontend.Circuit {
			circuit := &aes.AES256Wrapper{
				AESWrapper: aes.AESWrapper{Key: make([]frontend.Variable, 32)},
			}

			for i := 0; i < len(input); i++ {
				circuit.Plaintext[i] = input[i]
			}

			for i := 0; i < len(output); i++ {
				circuit.Ciphertext[i] = output[i]
			}
			return circuit
		},
	}

}

func Verify(params []byte) bool {
	var inputParams *InputVerifyParams
	err := json.Unmarshal(params, &inputParams)
	if err != nil {
		log.Err(err)
		return false
	}

	if verifier, ok := verifiers[inputParams.Cipher]; ok {
		return verifier.Verify(mustHex(inputParams.Proof), mustHex(inputParams.Input), mustHex(inputParams.Output))
	}
	return false
}
