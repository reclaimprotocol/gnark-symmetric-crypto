package impl

import (
	"bytes"
	"fmt"
	"gnark-symmetric-crypto/utils"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/rs/zerolog/log"
)

const BITS_PER_WORD = 32
const CHACHA_BLOCKS = 1

type ChaChaCircuit struct {
	In  [16 * CHACHA_BLOCKS][BITS_PER_WORD]frontend.Variable `gnark:",public"`
	Out [16 * CHACHA_BLOCKS][BITS_PER_WORD]frontend.Variable `gnark:",public"`
}

func (c *ChaChaCircuit) Define(_ frontend.API) error {
	return nil
}

const AES_BLOCKS = 4

type AESWrapper struct {
	Plaintext  [AES_BLOCKS * 16]frontend.Variable `gnark:",public"`
	Ciphertext [AES_BLOCKS * 16]frontend.Variable `gnark:",public"`
}

func (circuit *AESWrapper) Define(_ frontend.API) error {
	return nil
}

type Verifier interface {
	Verify(proof []byte, publicSignals []uint8) bool
}

type ChachaVerifier struct {
	vk groth16.VerifyingKey
}

func (cv *ChachaVerifier) Verify(proof []byte, publicSignals []uint8) bool {

	if len(publicSignals) != 128 {
		fmt.Printf("public signals must be 128 bytes, not %d\n", len(publicSignals))
		return false
	}

	witness := &ChaChaCircuit{}

	bSignals := utils.BytesToUint32BEBits(publicSignals)

	ciphertext := bSignals[:len(bSignals)/2]
	plaintext := bSignals[len(bSignals)/2:]

	for i := 0; i < len(witness.In); i++ {
		for j := 0; j < len(witness.In[i]); j++ {
			witness.In[i][j] = plaintext[i][j]
			witness.Out[i][j] = ciphertext[i][j]
		}
	}

	wtns, err := frontend.NewWitness(witness, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		log.Err(err)
		return false
	}

	gProof := groth16.NewProof(ecc.BN254)
	_, err = gProof.ReadFrom(bytes.NewBuffer(proof))
	if err != nil {
		fmt.Println(err)
		return false
	}
	err = groth16.Verify(gProof, cv.vk, wtns)
	if err != nil {
		fmt.Println(err)
	}
	return err == nil
}

type AESVerifier struct {
	vk groth16.VerifyingKey
}

func (av *AESVerifier) Verify(bProof []byte, publicSignals []uint8) bool {

	if len(publicSignals) != 128 {
		return false
	}

	ciphertext := publicSignals[:len(publicSignals)/2]
	plaintext := publicSignals[len(publicSignals)/2:]

	witness := &AESWrapper{}
	for i := 0; i < len(plaintext); i++ {
		witness.Plaintext[i] = plaintext[i]
		witness.Ciphertext[i] = ciphertext[i]
	}

	wtns, err := frontend.NewWitness(witness, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		fmt.Println(err)
		return false
	}

	gProof := groth16.NewProof(ecc.BN254)
	_, err = gProof.ReadFrom(bytes.NewBuffer(bProof))
	if err != nil {
		fmt.Println(err)
		return false
	}
	err = groth16.Verify(gProof, av.vk, wtns)
	if err != nil {
		fmt.Println(err)
		return false
	}

	return true
}
