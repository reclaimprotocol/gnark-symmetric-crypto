package impl

import (
	"bytes"
	"encoding/json"
	"fmt"
	"gnark-symmetric-crypto/utils"
	"sync"

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

const AES_BLOCKS = 1

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

	if len(publicSignals) != 1024 {
		return false
	}

	witness := &ChaChaCircuit{}

	ciphertext := publicSignals[:len(publicSignals)/2]
	plaintext := publicSignals[len(publicSignals)/2:]

	for i := 0; i < len(witness.In); i++ {
		for j := 0; j < len(witness.In[i]); j++ {
			witness.In[i][j] = plaintext[i*32+((j/8)*8+(7-j%8))]
			witness.Out[i][j] = ciphertext[i*32+((j/8)*8+(7-j%8))]
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

	if len(publicSignals) != 1024 {
		return false
	}

	ciphertext := utils.BitsToBytesBE(publicSignals[:len(publicSignals)/2])
	plaintext := utils.BitsToBytesBE(publicSignals[len(publicSignals)/2:])

	var proofs [][]byte
	er := json.Unmarshal(bProof, &proofs)
	if er != nil {
		fmt.Println(er)
		return false
	}

	numProofs := len(proofs)
	ptLen := len(plaintext) / numProofs
	results := make([]bool, numProofs)

	wg := sync.WaitGroup{}
	wg.Add(numProofs)

	for i := 0; i < numProofs; i++ {
		go func(chunk int) {
			defer wg.Done()
			witness := &AESWrapper{}
			for j := 0; j < ptLen; j++ {
				witness.Plaintext[j] = plaintext[chunk*ptLen+j]
				witness.Ciphertext[j] = ciphertext[chunk*ptLen+j]
			}

			wtns, err := frontend.NewWitness(witness, ecc.BN254.ScalarField(), frontend.PublicOnly())
			if err != nil {
				fmt.Println(err)
				return
			}

			gProof := groth16.NewProof(ecc.BN254)
			_, err = gProof.ReadFrom(bytes.NewBuffer(proofs[chunk]))
			if err != nil {
				fmt.Println(err)
				return
			}
			err = groth16.Verify(gProof, av.vk, wtns)
			if err != nil {
				fmt.Println(err)
				return
			}
			results[chunk] = true
		}(i)
	}

	wg.Wait()

	res := true
	for i := 0; i < len(results); i++ {
		res = res && results[i]
	}

	return res
}