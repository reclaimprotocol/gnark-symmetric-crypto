package circuits

import (
	"bytes"
	"gnark-symmetric-crypto/circuits/chachaV3"
	"gnark-symmetric-crypto/utils"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/rs/zerolog/log"
)

type Verifier interface {
	Verify(proof, input, output []byte) bool
}

type ChachaVerifier struct {
	vk groth16.VerifyingKey
}

func (cv *ChachaVerifier) Verify(proof, input, output []byte) bool {

	if len(input) != len(output) ||
		len(input) != 64*chachaV3.Blocks {
		return false
	}

	uplaintext := utils.BytesToUint32BERaw(input)
	uciphertext := utils.BytesToUint32BERaw(output)

	witness := chachaV3.ChaChaCircuit{}
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
	vk        groth16.VerifyingKey
	wrapMaker func(input, output []byte) frontend.Circuit
}

func (av *AESVerifier) Verify(proof, input, output []byte) bool {

	witness := av.wrapMaker(input, output)

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
