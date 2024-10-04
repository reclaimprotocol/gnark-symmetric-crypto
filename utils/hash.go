package utils

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/hash"
	"math/big"
)

func HashBN254(data []byte) ([]byte, error) {
	hasher := hash.Hash.New(hash.MIMC_BN254)

	// Ensure input length is a multiple of the field modulus size
	fieldSize := hasher.BlockSize()
	paddedLength := ((len(data) + fieldSize - 1) / fieldSize) * fieldSize
	paddedMsg := make([]byte, paddedLength)
	copy(paddedMsg, data)

	// Check if any field element is larger than the modulus
	modulus := ecc.BN254.ScalarField()
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

	_, err := hasher.Write(paddedMsg)
	if err != nil {
		return nil, err
	}
	hashV := hasher.Sum(nil)
	return hashV, nil
}
