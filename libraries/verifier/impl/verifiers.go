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
	Nonce   [12]frontend.Variable              `gnark:",public"`
	Counter frontend.Variable                  `gnark:",public"`
	In      [AES_BLOCKS * 16]frontend.Variable `gnark:",public"`
	Out     [AES_BLOCKS * 16]frontend.Variable `gnark:",public"`
}

func (circuit *AESWrapper) Define(_ frontend.API) error {
	return nil
}

const Threshold = 2

type OPRFData struct {
	DomainSeparator frontend.Variable `gnark:",public"`
	Mask            frontend.Variable

	Responses    [Threshold]twistededwards.Point `gnark:",public"` // responses per each node
	Coefficients [Threshold]frontend.Variable    `gnark:",public"` // coeffs for reconstructing point & public key

	// Proofs of DLEQ per node
	SharePublicKeys [Threshold]twistededwards.Point `gnark:",public"`
	C               [Threshold]frontend.Variable    `gnark:",public"`
	R               [Threshold]frontend.Variable    `gnark:",public"`

	Output twistededwards.Point `gnark:",public"`
}

type ChachaOPRFCircuit struct {
	Key     [8][BITS_PER_WORD]frontend.Variable
	Counter [BITS_PER_WORD]frontend.Variable                           `gnark:",public"`
	Nonce   [3][BITS_PER_WORD]frontend.Variable                        `gnark:",public"`
	In      [16 * CHACHA_OPRF_BLOCKS][BITS_PER_WORD]frontend.Variable  `gnark:",public"` // ciphertext
	Out     [16 * CHACHA_OPRF_BLOCKS][BITS_PER_WORD]frontend.Variable  // plaintext
	BitMask [16 * CHACHA_OPRF_BLOCKS * BITS_PER_WORD]frontend.Variable `gnark:",public"` // bit mask for bits being hashed

	// Length of "secret data" elements to be hashed. In bytes
	Len frontend.Variable `gnark:",public"`

	OPRF OPRFData
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
		witness.In[i] = plaintext[i]
		witness.Out[i] = ciphertext[i]
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
	var iParams *InputChachaOPRFParams
	err := json.Unmarshal(publicSignals, &iParams)
	if err != nil {
		fmt.Println(err)
		return false
	}

	oprf := iParams.OPRF
	if oprf == nil {
		fmt.Println("OPRF params are empty")
		return false
	}

	if len(oprf.C) != Threshold || len(oprf.R) != Threshold ||
		len(oprf.NodeResponses) != Threshold || len(oprf.NodeIndexes) != Threshold {
		fmt.Println("OPRF params are invalid")
		return false
	}

	nodePublicKeys := make([]twistededwards.Point, Threshold)
	resps := make([]twistededwards.Point, Threshold)
	cs := make([]frontend.Variable, Threshold)
	rs := make([]frontend.Variable, Threshold)
	coeffs := make([]frontend.Variable, Threshold)

	for i := 0; i < Threshold; i++ {
		nodePublicKeys[i] = utils.UnmarshalPoint(oprf.NodePublicKeys[i])
		coeffs[i] = utils.Coeff(oprf.NodeIndexes[i], oprf.NodeIndexes)
		resps[i] = utils.UnmarshalPoint(oprf.NodeResponses[i])
		cs[i] = new(big.Int).SetBytes(iParams.OPRF.C[i])
		rs[i] = new(big.Int).SetBytes(iParams.OPRF.R[i])

	}

	witness := &ChachaOPRFCircuit{
		OPRF: OPRFData{
			DomainSeparator: new(big.Int).SetBytes(iParams.OPRF.DomainSeparator),
			Output:          utils.UnmarshalPoint(iParams.OPRF.Output),
		},
	}

	copy(witness.OPRF.SharePublicKeys[:], nodePublicKeys)
	copy(witness.OPRF.Coefficients[:], coeffs)
	copy(witness.OPRF.Responses[:], resps)
	copy(witness.OPRF.C[:], cs)
	copy(witness.OPRF.R[:], rs)

	nonce := utils.BytesToUint32LEBits(iParams.Nonce)
	counter := utils.Uint32ToBits(iParams.Counter)

	copy(witness.In[:], utils.BytesToUint32BEBits(iParams.Input))
	copy(witness.Nonce[:], nonce)
	witness.Counter = counter

	utils.SetBitmask(witness.BitMask[:], iParams.OPRF.Pos, iParams.OPRF.Len)
	witness.Len = iParams.OPRF.Len

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
