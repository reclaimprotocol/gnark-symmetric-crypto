package impl

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"gnark-symmetric-crypto/utils"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
)

const BITS_PER_WORD = 32
const CHACHA_BLOCKS = 1
const AES_BLOCKS = 4
const CHACHA_OPRF_BLOCKS = 2

type ChaChaCircuit struct {
	Counter [BITS_PER_WORD]frontend.Variable                     `gnark:",public"`
	Nonce   [3][BITS_PER_WORD]frontend.Variable                  `gnark:",public"`
	In      [16 * CHACHA_BLOCKS][BITS_PER_WORD]frontend.Variable `gnark:",public"`
	Out     [16 * CHACHA_BLOCKS][BITS_PER_WORD]frontend.Variable `gnark:",public"`
}

func (c *ChaChaCircuit) Define(_ frontend.API) error {
	return nil
}

type AESWrapper struct {
	Nonce      [12]frontend.Variable              `gnark:",public"`
	Counter    frontend.Variable                  `gnark:",public"`
	Plaintext  [AES_BLOCKS * 16]frontend.Variable `gnark:",public"`
	Ciphertext [AES_BLOCKS * 16]frontend.Variable `gnark:",public"`
}

func (circuit *AESWrapper) Define(_ frontend.API) error {
	return nil
}

type OPRFData struct {
	DomainSeparator frontend.Variable    `gnark:",public"`
	ServerResponse  twistededwards.Point `gnark:",public"`
	ServerPublicKey twistededwards.Point `gnark:",public"`
	Output          twistededwards.Point `gnark:",public"` // after this point is hashed it will be the "nullifier"
	// Proof values of DLEQ that ServerResponse was created with the same private key as server public key
	C frontend.Variable `gnark:",public"`
	S frontend.Variable `gnark:",public"`
}

type ChachaOPRFCircuit struct {
	In  [16 * CHACHA_OPRF_BLOCKS][BITS_PER_WORD]frontend.Variable `gnark:",public"` // ciphertext
	Out [16 * CHACHA_OPRF_BLOCKS][BITS_PER_WORD]frontend.Variable `gnark:",public"` // plaintext

	// position & length of "secret data" to be hashed
	Pos frontend.Variable `gnark:",public"`
	Len frontend.Variable `gnark:",public"`

	OPRF *OPRFData
}

func (circuit *ChachaOPRFCircuit) Define(_ frontend.API) error {
	return nil
}

type Verifier interface {
	Verify(proof []byte, publicSignals []uint8) bool
}

type ChachaVerifier struct {
	vk groth16.VerifyingKey
}

func (cv *ChachaVerifier) Verify(proof []byte, publicSignals []uint8) bool {

	if len(publicSignals) != 128+12+4 { // in, nonce, counter, out
		fmt.Printf("public signals must be 144 bytes, not %d\n", len(publicSignals))
		return false
	}

	witness := &ChaChaCircuit{}

	bOut := publicSignals[:64]
	bIn := publicSignals[64+12+4:]
	bNonce := publicSignals[64 : 64+12]
	bCounter := publicSignals[64+12 : 64+12+4]

	out := utils.BytesToUint32BEBits(bOut)
	in := utils.BytesToUint32BEBits(bIn)
	nonce := utils.BytesToUint32LEBits(bNonce)
	counter := utils.BytesToUint32LEBits(bCounter)

	copy(witness.In[:], in)
	copy(witness.Out[:], out)
	copy(witness.Nonce[:], nonce)
	witness.Counter = counter[0]

	wtns, err := frontend.NewWitness(witness, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		fmt.Println(err)
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

	if len(publicSignals) != 128+12+4 { // plaintext, nonce, counter, ciphertext
		return false
	}

	ciphertext := publicSignals[:64]
	plaintext := publicSignals[64+12+4:]
	nonce := publicSignals[64 : 64+12]
	bCounter := publicSignals[64+12 : 64+12+4]

	witness := &AESWrapper{}

	for i := 0; i < len(plaintext); i++ {
		witness.Plaintext[i] = plaintext[i]
		witness.Ciphertext[i] = ciphertext[i]
	}

	for i := 0; i < len(nonce); i++ {
		witness.Nonce[i] = nonce[i]
	}

	witness.Counter = binary.BigEndian.Uint32(bCounter)

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

type ChachaOPRFVerifier struct {
	vk groth16.VerifyingKey
}

func (cv *ChachaOPRFVerifier) Verify(proof []byte, publicSignals []uint8) bool {

	witness := &ChachaOPRFCircuit{}

	var params *InputChachaOPRFParams
	err := json.Unmarshal(publicSignals, &params)
	if err != nil {
		fmt.Println(err)
		return false
	}

	copy(witness.In[:], utils.BytesToUint32BEBits(params.Input))
	copy(witness.Out[:], utils.BytesToUint32BEBits(params.Output))
	witness.Pos = params.OPRF.Pos
	witness.Len = params.OPRF.Len
	witness.OPRF = &OPRFData{
		ServerResponse:  utils.UnmarshalPoint(params.OPRF.ServerResponse),
		ServerPublicKey: utils.UnmarshalPoint(params.OPRF.ServerPublicKey),
		Output:          utils.UnmarshalPoint(params.OPRF.Output),
		C:               new(big.Int).SetBytes(params.OPRF.C),
		S:               new(big.Int).SetBytes(params.OPRF.S),
	}

	wtns, err := frontend.NewWitness(witness, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		fmt.Println(err)
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
