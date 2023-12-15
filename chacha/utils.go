package chacha

import (
	"encoding/binary"

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
