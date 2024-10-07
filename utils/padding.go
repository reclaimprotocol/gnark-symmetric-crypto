package utils

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

func PadMsg(data []*big.Int) []fr.Element {
	paddedMsg := make([]fr.Element, len(data))
	for i, value := range data {
		paddedMsg[i].SetBytes(value.Bytes())
	}
	return paddedMsg
}
