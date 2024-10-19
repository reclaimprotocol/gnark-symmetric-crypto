package chachaV3_oprf

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/constraint/solver"
)

func init() {
	solver.RegisterHint(GetHints()...)
}

func GetHints() []solver.Hint {
	return []solver.Hint{
		extractData,
	}
}

const bytesPerElement = 31
const bitsPerElement = bytesPerElement * 8
const maxSize = bitsPerElement * 2

func extractData(_ *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	if len(inputs) != 2+512*Blocks {
		return fmt.Errorf("expecting 3+254 inputs, got %d", len(inputs))
	}
	if len(outputs) != 2 {
		return fmt.Errorf("expecting one output")
	}

	inPos := inputs[0]
	inSize := inputs[1]
	bits := inputs[2:]
	if !inPos.IsUint64() {
		return fmt.Errorf("pos must be int")
	}
	if !inSize.IsUint64() {
		return fmt.Errorf("size must be int")
	}

	pos := inPos.Uint64()
	size := inSize.Uint64()
	if size > maxSize {
		return fmt.Errorf("size must be <= %d", maxSize)
	}
	if pos+size > 512*Blocks {
		return fmt.Errorf("out of bounds")
	}

	if size%8 != 0 {
		return fmt.Errorf("size not a multiple of 8")
	}

	bits = bits[pos : pos+size]
	bitsSize := len(bits)
	byteSize := bitsSize / 8

	res1, res2 := outputs[0], outputs[1]
	var res1Bits, res2Bits []*big.Int
	if byteSize < 31 {
		LEtoBE(bits, byteSize)
		res1Bits = bits
		res2 = big.NewInt(0)
	} else {
		res1Bits = bits[:bitsPerElement]
		res2Bits = bits[bitsPerElement:]
		LEtoBE(res1Bits, bytesPerElement)
		LEtoBE(res2Bits, len(res2Bits)/8)
	}

	for i := 0; i < len(res1Bits); i++ {
		res1.SetBit(res1, i, uint(res1Bits[i].Uint64()))
	}
	for i := 0; i < len(res2Bits); i++ {
		res2.SetBit(res2, i, uint(res2Bits[i].Uint64()))
	}
	return nil
}

func LEtoBE(bits []*big.Int, byteSize int) {
	for i := 0; i < byteSize/2; i++ {
		b1 := 8 * i
		b2 := (byteSize - i - 1) * 8
		for j := 0; j < 8; j++ {
			bits[b1+j], bits[b2+j] = bits[b2+j], bits[b1+j]
		}
	}
}
