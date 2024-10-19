package chachaV3_oprf

import (
	"gnark-symmetric-crypto/utils"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
	"github.com/consensys/gnark/std/math/bits"
)

const Blocks = 2

type NullifierData struct {
	Mask      frontend.Variable
	Response  twistededwards.Point `gnark:",public"`
	Nullifier twistededwards.Point `gnark:",public"`
	// Proof of DLEQ that Response was created with the same private key as server public key
	ServerPublicKey twistededwards.Point `gnark:",public"`
	Challenge       frontend.Variable    `gnark:",public"`
	Proof           frontend.Variable    `gnark:",public"`
}

type ChaChaCircuit struct {
	Key     [8][BITS_PER_WORD]frontend.Variable
	Counter [BITS_PER_WORD]frontend.Variable
	Nonce   [3][BITS_PER_WORD]frontend.Variable
	In      [16 * Blocks][BITS_PER_WORD]frontend.Variable `gnark:",public"`
	Out     [16 * Blocks][BITS_PER_WORD]frontend.Variable `gnark:",public"`
	Pos     frontend.Variable                             `gnark:",public"`
	Size    frontend.Variable                             `gnark:",public"`

	OPRF *NullifierData
}

func (c *ChaChaCircuit) Define(api frontend.API) error {
	pureOut := make([]frontend.Variable, 16*Blocks*BITS_PER_WORD)
	var state [16][BITS_PER_WORD]frontend.Variable
	counter := c.Counter

	var one [BITS_PER_WORD]frontend.Variable
	copy(one[:], api.ToBinary(1, 32))

	c1 := bits.ToBinary(api, 0x61707865, bits.WithNbDigits(32))
	c2 := bits.ToBinary(api, 0x3320646e, bits.WithNbDigits(32))
	c3 := bits.ToBinary(api, 0x79622d32, bits.WithNbDigits(32))
	c4 := bits.ToBinary(api, 0x6b206574, bits.WithNbDigits(32))
	for b := 0; b < Blocks; b++ {
		// Fill state. Start with constants

		copy(state[0][:], c1[:])
		copy(state[1][:], c2[:])
		copy(state[2][:], c3[:])
		copy(state[3][:], c4[:])

		// set key
		copy(state[4:], c.Key[:])
		// set counter
		state[12] = counter
		// set nonce
		copy(state[13:], c.Nonce[:])
		// modify state with round function
		Round(api, &state)
		// produce keystream from state
		Serialize(&state)

		// xor keystream with input
		var ciphertext [16][BITS_PER_WORD]frontend.Variable
		for i, s := range state {
			xor32(api, &c.In[b*16+i], &s, &ciphertext[i])
		}

		// check that output matches ciphertext
		for i := 0; i < 16; i++ {
			for j := 0; j < BITS_PER_WORD; j++ {
				api.AssertIsEqual(c.Out[b*16+i][j], ciphertext[i][j])
			}
		}
		// increment counter for next block
		if b+1 < Blocks {
			add32(api, &counter, &one)
		}
	}

	// flattern input (plaintext)
	for i := 0; i < len(c.Out); i++ {
		word := i * 32
		for j := 0; j < BITS_PER_WORD; j++ {
			nByte := 3 - j/8
			pureOut[word+j] = c.Out[i][nByte*8+j%8]
		}
	}

	inputs := make([]frontend.Variable, 2+len(pureOut))
	copy(inputs[2:], pureOut)
	inputs[0] = c.Pos
	inputs[1] = c.Size
	api.AssertIsLessOrEqual(c.Size, 248)
	api.AssertIsLessOrEqual(c.Pos, Blocks*512-248)

	// extract "secret data" from pos & size
	res, err := api.Compiler().NewHint(extractData, 1, inputs...)
	if err != nil {
		return err
	}

	oprf := &utils.NullifierData{
		SecretData:      res[0],
		Mask:            c.OPRF.Mask,
		Response:        c.OPRF.Response,
		Nullifier:       c.OPRF.Nullifier,
		ServerPublicKey: c.OPRF.ServerPublicKey,
		Challenge:       c.OPRF.Challenge,
		Proof:           c.OPRF.Proof,
	}
	return utils.CheckNullifier(api, oprf)
}
