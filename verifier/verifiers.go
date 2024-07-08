package verifier

import (
	"bytes"
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

func (c *ChaChaCircuit) Define(api frontend.API) error {
	return nil
}

const AES_BLOCKS = 4

type AESWrapper struct {
	Plaintext  [AES_BLOCKS * 16]frontend.Variable `gnark:",public"`
	Ciphertext [AES_BLOCKS * 16]frontend.Variable `gnark:",public"`
}

func (circuit *AESWrapper) Define(api frontend.API) error {
	return nil
}

type Verifier interface {
	Verify(proof, input, output []byte) bool
}

type ChachaVerifier struct {
	vk groth16.VerifyingKey
}

func (cv *ChachaVerifier) Verify(proof, input, output []byte) bool {

	if len(input) != len(output) ||
		len(input) != 64*CHACHA_BLOCKS {
		return false
	}

	uplaintext := utils.BytesToUint32BERaw(input)
	uciphertext := utils.BytesToUint32BERaw(output)

	witness := ChaChaCircuit{}
	copy(witness.In[:], utils.UintsToBits(uplaintext))
	copy(witness.Out[:], utils.UintsToBits(uciphertext))

	wtns, err := frontend.NewWitness(&witness, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		log.Err(err)
		return false
	}

	gProof := groth16.NewProof(ecc.BN254)
	_, err = gProof.ReadFrom(bytes.NewBuffer(proof))
	if err != nil {
		log.Err(err)
		return false
	}
	err = groth16.Verify(gProof, cv.vk, wtns)
	if err != nil {
		log.Err(err)
	}
	return err == nil
}

type AESVerifier struct {
	vk groth16.VerifyingKey
}

func (av *AESVerifier) Verify(proof, input, output []byte) bool {

	witness := &AESWrapper{}

	for i := 0; i < len(input); i++ {
		witness.Plaintext[i] = input[i]
	}

	for i := 0; i < len(output); i++ {
		witness.Ciphertext[i] = output[i]
	}

	wtns, err := frontend.NewWitness(witness, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		log.Err(err)
		return false
	}

	gProof := groth16.NewProof(ecc.BN254)
	_, err = gProof.ReadFrom(bytes.NewBuffer(proof))
	if err != nil {
		log.Err(err)
		return false
	}
	err = groth16.Verify(gProof, av.vk, wtns)
	if err != nil {
		log.Err(err)
	}
	return err == nil
}
