package chachaV3_oprf

import (
	"gnark-symmetric-crypto/circuits/oprf"
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
	"github.com/consensys/gnark/std/math/bits"
	"github.com/consensys/gnark/std/math/cmp"
)

const Blocks = 2
const BytesPerElement = 31

type OPRFData struct {
	Mask            frontend.Variable
	DomainSeparator frontend.Variable    `gnark:",public"`
	ServerResponse  twistededwards.Point `gnark:",public"`
	ServerPublicKey twistededwards.Point `gnark:",public"`
	Output          twistededwards.Point `gnark:",public"` // after this point is hashed it will be the "nullifier"
	// Proof values of DLEQ that ServerResponse was created with the same private key as server public key
	C frontend.Variable `gnark:",public"`
	S frontend.Variable `gnark:",public"`
}

type ChachaOPRFCircuit struct {
	Key     [8][BITS_PER_WORD]frontend.Variable
	Counter [BITS_PER_WORD]frontend.Variable               `gnark:",public"`
	Nonce   [3][BITS_PER_WORD]frontend.Variable            `gnark:",public"`
	In      [16 * Blocks][BITS_PER_WORD]frontend.Variable  `gnark:",public"` // ciphertext
	Out     [16 * Blocks][BITS_PER_WORD]frontend.Variable  // plaintext
	BitMask [16 * Blocks * BITS_PER_WORD]frontend.Variable `gnark:",public"` // bit mask for bits being hashed

	// Length of "secret data" elements to be hashed. In bytes
	Len frontend.Variable `gnark:",public"`

	OPRF OPRFData
}

func (c *ChachaOPRFCircuit) Define(api frontend.API) error {
	outBits := make([]frontend.Variable, 16*Blocks*BITS_PER_WORD)
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
		var output [16][BITS_PER_WORD]frontend.Variable
		for i, s := range state {
			xor32(api, &c.In[b*16+i], &s, &output[i])
		}

		// check that output matches calculated output
		for i := 0; i < 16; i++ {
			for j := 0; j < BITS_PER_WORD; j++ {
				api.AssertIsEqual(c.Out[b*16+i][j], output[i][j])
			}
		}
		// increment counter for next block
		if b+1 < Blocks {
			add32(api, &counter, &one)
		}
	}

	// flatten result bits array
	for i := 0; i < len(c.Out); i++ {
		word := i * 32
		for j := 0; j < BITS_PER_WORD; j++ {
			nByte := 3 - j/8 // switch endianness back to original
			outBits[word+j] = c.Out[i][nByte*8+j%8]
		}
	}

	pow1 := frontend.Variable(1)
	pow2 := frontend.Variable(0)
	res1 := frontend.Variable(0)
	res2 := frontend.Variable(0)
	totalBits := frontend.Variable(0)

	for i := 0; i < 128; i++ {
		for j := 0; j < 8; j++ {

			bitIndex := i*8 + j
			bitIsSet := c.BitMask[bitIndex]
			bit := api.Select(bitIsSet, outBits[bitIndex], 0)

			res1 = api.Add(res1, api.Mul(bit, pow1))
			res2 = api.Add(res2, api.Mul(bit, pow2))

			n := api.Add(bitIsSet, 1) // do we need to multiply power by 2?
			pow2 = api.Mul(pow2, n)
			pow1 = api.Mul(pow1, n)

			totalBits = api.Add(totalBits, bitIsSet)

			r1Done := api.IsZero(api.Sub(totalBits, BytesPerElement*8)) // are we done with 1st number?
			pow1 = api.Mul(pow1, api.Sub(1, r1Done))                    // set pow1 to zero if yes
			pow2 = api.Add(pow2, r1Done)                                // set pow2 to 1 to start increasing

		}
	}

	comparator := cmp.NewBoundedComparator(api, big.NewInt(16*Blocks*BITS_PER_WORD-BytesPerElement*8*2), false)
	comparator.AssertIsLessEq(totalBits, BytesPerElement*8*2)
	api.AssertIsEqual(totalBits, api.Mul(c.Len, 8)) // and that we processed correct number of bits

	// check that OPRF output was created from secret data by a server with a specific public key
	oprfData := &oprf.OPRFData{
		SecretData:      [2]frontend.Variable{res1, res2},
		DomainSeparator: c.OPRF.DomainSeparator,
		Mask:            c.OPRF.Mask,
		Response:        c.OPRF.ServerResponse,
		Output:          c.OPRF.Output,
		ServerPublicKey: c.OPRF.ServerPublicKey,
		C:               c.OPRF.C,
		S:               c.OPRF.S,
	}
	return oprf.VerifyOPRF(api, oprfData)
}
