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

const maxSize = 254

func extractData(_ *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	if len(inputs) != 2+512*Blocks {
		return fmt.Errorf("expecting 3+254 inputs, got %d", len(inputs))
	}
	if len(outputs) != 1 {
		return fmt.Errorf("expecting one output")
	}

	pos := inputs[0]
	size := inputs[1]
	bits := inputs[2:]
	if !pos.IsUint64() {
		return fmt.Errorf("pos must be int")
	}
	if !size.IsUint64() {
		return fmt.Errorf("size must be int")
	}

	if size.Uint64() > maxSize {
		return fmt.Errorf("size must be < %d", maxSize)
	}
	if pos.Uint64()+size.Uint64() > 512*Blocks {
		return fmt.Errorf("out of bounds")
	}

	if size.Uint64()%8 != 0 {
		return fmt.Errorf("size not a multiple of 8")
	}

	bits = bits[pos.Uint64() : pos.Uint64()+size.Uint64()]
	bitsSize := len(bits)
	byteSize := bitsSize / 8
	// switch endianness
	for i := 0; i < byteSize/2; i++ {
		b1 := 8 * i
		b2 := (byteSize - i - 1) * 8
		for j := 0; j < 8; j++ {
			bits[b1+j], bits[b2+j] = bits[b2+j], bits[b1+j]
		}
	}

	res := outputs[0]

	for i := 0; i < bitsSize; i++ {
		if !bits[i].IsUint64() || bits[i].Uint64() > 1 {
			return fmt.Errorf("invalid bit value, must be 0 or 1 got %d", bits[i].Uint64())
		}

		res.SetBit(res, i, uint(bits[i].Uint64()))
	}
	return nil
}
