package utils

import (
	"math/big"
)

func PadMsg(data []byte, fieldSize int, modulus *big.Int) []byte {
	// Ensure input length is a multiple of the field modulus size
	paddedLength := ((len(data) + fieldSize - 1) / fieldSize) * fieldSize
	paddedMsg := make([]byte, paddedLength)
	copy(paddedMsg, data)

	// Check if any field element is larger than the modulus
	for i := 0; i < len(paddedMsg); i += fieldSize {
		element := new(big.Int).SetBytes(paddedMsg[i : i+fieldSize])
		element.Mod(element, modulus)
		// Convert the modded element back to bytes and update paddedMsg
		elementBytes := element.Bytes()
		// Ensure the byte slice is the correct length
		if len(elementBytes) < fieldSize {
			padding := make([]byte, fieldSize-len(elementBytes))
			elementBytes = append(padding, elementBytes...)
		}
		copy(paddedMsg[i:i+fieldSize], elementBytes)
	}

	return paddedMsg
}
