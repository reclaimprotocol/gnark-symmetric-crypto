package circuits

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"gnark-symmetric-crypto/circuits/chachaV3"
	"gnark-symmetric-crypto/utils"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/rs/zerolog/log"
)

type InputVerifyParams struct {
	Name       string `json:"name"`
	Proof      string `json:"proof"`
	Plaintext  string `json:"plaintext"`
	Ciphertext string `json:"ciphertext"`
}

//go:embed r1cs
var r1csEmbedded []byte

//go:embed vk
var vkEmbedded []byte
var r1css constraint.ConstraintSystem
var vk groth16.VerifyingKey

func init() {
	r1css = groth16.NewCS(ecc.BN254)
	_, err := r1css.ReadFrom(bytes.NewBuffer(r1csEmbedded))
	if err != nil {
		panic(err)
	}

	vk = groth16.NewVerifyingKey(ecc.BN254)
	_, err = vk.ReadFrom(bytes.NewBuffer(vkEmbedded))
	if err != nil {
		panic(err)
	}
}

func Verify(params []byte) bool {
	var inputParams *InputVerifyParams
	err := json.Unmarshal(params, &inputParams)
	if err != nil {
		log.Err(err)
		return false
	}

	uplaintext := utils.BytesToUint32BERaw(mustHex(inputParams.Plaintext))
	uciphertext := utils.BytesToUint32BERaw(mustHex(inputParams.Ciphertext))

	witness := chachaV3.ChaChaCircuit{}
	copy(witness.In[:], utils.UintsToBits(uplaintext))
	copy(witness.Out[:], utils.UintsToBits(uciphertext))

	wtns, err := frontend.NewWitness(&witness, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		panic(err)
	}

	gProof := groth16.NewProof(ecc.BN254)
	_, err = gProof.ReadFrom(bytes.NewBuffer(mustHex(inputParams.Proof)))
	if err != nil {
		panic(err)
	}
	err = groth16.Verify(gProof, vk, wtns)
	return err == nil
}
