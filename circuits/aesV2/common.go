package aes_v2

import (
	"github.com/consensys/gnark/frontend"
)

const BLOCKS = 1

type AESWrapper struct {
	Key        []frontend.Variable
	Nonce      [12]frontend.Variable
	Counter    frontend.Variable
	Plaintext  [BLOCKS * 16]frontend.Variable `gnark:",public"`
	Ciphertext [BLOCKS * 16]frontend.Variable `gnark:",public"`
}

type AESGadget struct {
	api   frontend.API
	sbox0 [256]frontend.Variable
	RCon  [11]frontend.Variable
	t     [4][256]frontend.Variable
}

// retuns AESGadget instance which can be used inside a circuit
func NewAESGadget(api frontend.API) AESGadget {

	RCon := [11]frontend.Variable{0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36}

	return AESGadget{api: api, sbox0: sbox0, RCon: RCon, t: T}
}

// aes128 encrypt function
func (aes *AESGadget) SubBytes(state [16]frontend.Variable) [16]frontend.Variable {
	var newState [16]frontend.Variable
	for i := 0; i < 16; i++ {
		newState[i] = aes.Subw(aes.sbox0, state[i])
	}
	return newState
}

// xor on bits of two frontend.Variables
func (aes *AESGadget) VariableXor(a frontend.Variable, b frontend.Variable, size int) frontend.Variable {
	bitsA := aes.api.ToBinary(a, size)
	bitsB := aes.api.ToBinary(b, size)
	x := make([]frontend.Variable, size)
	for i := 0; i < size; i++ {
		x[i] = aes.api.Xor(bitsA[i], bitsB[i])
	}
	return aes.api.FromBinary(x...)
}

func (aes *AESGadget) XorByte(a frontend.Variable, bitsB []frontend.Variable) frontend.Variable {
	if len(bitsB) != 8 {
		panic("invalid byte len")
	}
	bitsA := aes.api.ToBinary(a, 8)
	x := make([]frontend.Variable, 8)
	for i := 0; i < 8; i++ {
		x[i] = aes.api.Xor(bitsA[i], bitsB[i])
	}
	return aes.api.FromBinary(x...)
}

func (aes *AESGadget) XorSubWords(a, b, c, d frontend.Variable, xk []frontend.Variable) []frontend.Variable {

	aa := aes.Subw(T[0], a)
	bb := aes.Subw(T[1], b)
	cc := aes.Subw(T[2], c)
	dd := aes.Subw(T[3], d)

	t0 := aes.api.ToBinary(aa, 32)
	t1 := aes.api.ToBinary(bb, 32)
	t2 := aes.api.ToBinary(cc, 32)
	t3 := aes.api.ToBinary(dd, 32)

	t4 := append(aes.api.ToBinary(xk[0], 8), aes.api.ToBinary(xk[1], 8)...)
	t4 = append(t4, aes.api.ToBinary(xk[2], 8)...)
	t4 = append(t4, aes.api.ToBinary(xk[3], 8)...)

	t := make([]frontend.Variable, 32)
	for i := 0; i < 32; i++ {
		t[i] = aes.api.Xor(t0[i], t1[i])
		t[i] = aes.api.Xor(t[i], t2[i])
		t[i] = aes.api.Xor(t[i], t3[i])
		t[i] = aes.api.Xor(t[i], t4[i])
	}

	newState := make([]frontend.Variable, 4)
	newState[0] = aes.api.FromBinary(t[:8]...)
	newState[1] = aes.api.FromBinary(t[8:16]...)
	newState[2] = aes.api.FromBinary(t[16:24]...)
	newState[3] = aes.api.FromBinary(t[24:32]...)
	return newState
}

// substitute word with naive lookup of sbox
func (aes *AESGadget) Subw(sbox [256]frontend.Variable, a frontend.Variable) frontend.Variable {
	out := frontend.Variable(0)
	for j := 0; j < 256; j++ {
		out = aes.api.Add(out, aes.api.Mul(aes.api.IsZero(aes.api.Sub(a, j)), sbox[j])) // api.Cmp instead of api.Sub works but is inefficient
	}
	return out
}

func (aes *AESGadget) createIV(counter frontend.Variable, iv []frontend.Variable) {
	aBits := aes.api.ToBinary(counter, 32)

	for i := 0; i < 4; i++ {
		iv[15-i] = aes.api.FromBinary(aBits[i*8 : i*8+8]...)
	}

}
