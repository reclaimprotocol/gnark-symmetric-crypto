package utils

import (
	"encoding/binary"
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

func BytesToUint32LE(in []uint8) []uints.U32 {

	var res []uints.U32
	for i := 0; i < len(in); i += 4 {
		t := binary.LittleEndian.Uint32(in[i:])
		res = append(res, uints.NewU32(t))
	}
	return res
}
func BytesToUint32BE(in []uint8) []uints.U32 {

	var res []uints.U32
	for i := 0; i < len(in); i += 4 {
		t := binary.BigEndian.Uint32(in[i:])
		res = append(res, uints.NewU32(t))
	}
	return res
}

func BytesToUint32BERaw(in []uint8) []frontend.Variable {

	var res []frontend.Variable
	for i := 0; i < len(in); i += 4 {
		t := binary.BigEndian.Uint32(in[i:])
		res = append(res, t)
	}
	return res
}

func BytesToUint32LERaw(in []uint8) []frontend.Variable {

	var res []frontend.Variable
	for i := 0; i < len(in); i += 4 {
		t := binary.LittleEndian.Uint32(in[i:])
		res = append(res, t)
	}
	return res
}

func Uint32ToBits(in frontend.Variable) [32]frontend.Variable {
	var b *big.Int
	switch it := in.(type) {
	case uint32:
		b = big.NewInt(int64(it))
	case int:
		b = big.NewInt(int64(it))
	default:
		panic("invalid type")
	}

	var res [32]frontend.Variable
	for i := 0; i < 32; i++ {
		res[i] = b.Bit(i)
	}
	return res
}

func Uint32ToBitsLE(in frontend.Variable) [32]frontend.Variable {
	var b *big.Int
	switch it := in.(type) {
	case uint32:
		b = big.NewInt(int64(it))
	case int:
		b = big.NewInt(int64(it))
	default:
		panic("invalid type")
	}

	var res [32]frontend.Variable
	for i := 0; i < 32; i++ {
		res[i] = b.Bit(31 - i)
	}
	return res
}

func UintsToBits(in []frontend.Variable) [][32]frontend.Variable {
	res := make([][32]frontend.Variable, len(in))
	for i := 0; i < len(in); i++ {
		res[i] = Uint32ToBits(in[i])
	}
	return res
}

func BitsToBytes32LE(in []uint8) []byte {
	res := make([]byte, len(in)/8)
	for i := 0; i < len(in); i++ {
		res[3-(i/8)] |= in[i] << (7 - (i % 8))
	}
	return res
}

func BitsToBytesLE(in [][]uint8) []byte {
	res := make([]byte, 0, len(in)*4)
	for i := 0; i < len(in); i++ {
		res = append(res, BitsToBytes32LE(in[i])...)
	}
	return res
}

func BitsToBytesBE(in []uint8) []byte {
	res := make([]byte, len(in)/8)
	for i := 0; i < len(res); i++ {
		for j := 0; j < 8; j++ {
			res[i] = res[i] | in[i*8+j]<<(7-j)
		}
	}
	return res
}

func BytesToBitsBE(bytes []uint8) []uint8 {
	bits := make([]uint8, len(bytes)*8)
	for i := 0; i < len(bytes); i++ {
		for j := 0; j < 8; j++ {
			bits[i*8+j] = (bytes[i] >> (7 - j)) & 1
		}

	}
	return bits
}
