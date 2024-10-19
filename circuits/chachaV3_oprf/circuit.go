package chachaV3_oprf

import (
	"gnark-symmetric-crypto/circuits/oprf"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
	"github.com/consensys/gnark/std/math/bits"
)

const Blocks = 2

type OPRFData struct {
	Mask            frontend.Variable
	ServerResponse  twistededwards.Point `gnark:",public"`
	ServerPublicKey twistededwards.Point `gnark:",public"`
	Output          twistededwards.Point `gnark:",public"`
	// Proof values of DLEQ that ServerResponse was created with the same private key as server public key
	C frontend.Variable `gnark:",public"`
	S frontend.Variable `gnark:",public"`
}

type ChachaOPRFCircuit struct {
	Key     [8][BITS_PER_WORD]frontend.Variable
	Counter [BITS_PER_WORD]frontend.Variable
	Nonce   [3][BITS_PER_WORD]frontend.Variable
	In      [16 * Blocks][BITS_PER_WORD]frontend.Variable // plaintext
	Out     [16 * Blocks][BITS_PER_WORD]frontend.Variable `gnark:",public"` // ciphertext

	// position & length of "secret data" to be hashed
	Pos frontend.Variable `gnark:",public"`
	Len frontend.Variable `gnark:",public"`

	OPRF *OPRFData
}

func (c *ChachaOPRFCircuit) Define(api frontend.API) error {
	inBits := make([]frontend.Variable, 16*Blocks*BITS_PER_WORD)
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
	for i := 0; i < len(c.In); i++ {
		word := i * 32
		for j := 0; j < BITS_PER_WORD; j++ {
			nByte := 3 - j/8 // switch endianness back
			inBits[word+j] = c.In[i][nByte*8+j%8]
		}
	}

	hintInputs := make([]frontend.Variable, 2+len(inBits))
	copy(hintInputs[2:], inBits)
	hintInputs[0] = c.Pos
	hintInputs[1] = c.Len
	api.AssertIsLessOrEqual(api.Add(c.Pos, c.Len), 512*Blocks)

	// extract "secret data" from pos & size
	res, err := api.Compiler().NewHint(extractData, 2, hintInputs...)
	if err != nil {
		return err
	}

	// check that OPRF output was created from secret data by a server with a specific public key
	oprfData := &oprf.OPRFData{
		SecretData:      [2]frontend.Variable{res[0], res[1]},
		Mask:            c.OPRF.Mask,
		Response:        c.OPRF.ServerResponse,
		Output:          c.OPRF.Output,
		ServerPublicKey: c.OPRF.ServerPublicKey,
		C:               c.OPRF.C,
		S:               c.OPRF.S,
	}
	return oprf.VerifyOPRF(api, oprfData)
}
