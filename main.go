package main

import (
	"crypto/rand"

	"log"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/reclaimprotocol/gnark-chacha20/chacha"
	"golang.org/x/crypto/chacha20"
)

func main() {
	err := generateGroth16()
	if err != nil {
		log.Fatal("groth16 error:", err)
	}
}

func generateGroth16() error {
	var circuit chacha.Circuit

	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		return err
	}

	pk, vk, err := groth16.Setup(r1cs)
	if err != nil {
		return err
	}

	bKey := []uint8{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f}

	bNonce := []uint8{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00}

	counter := uints.NewU32(1)

	bPt := make([]byte, 128)
	rand.Read(bPt)
	bCt := make([]byte, 128)

	cipher, err := chacha20.NewUnauthenticatedCipher(bKey, bNonce)
	if err != nil {
		return err
	}

	cipher.SetCounter(1)
	cipher.XORKeyStream(bCt, bPt)

	plaintext := chacha.BytesToUint32BE(bPt)

	ciphertext := chacha.BytesToUint32BE(bCt)

	witness := chacha.Circuit{}
	copy(witness.Key[:], chacha.BytesToUint32LE(bKey))
	copy(witness.Nonce[:], chacha.BytesToUint32LE(bNonce))
	witness.Counter = counter
	copy(witness.In[:], plaintext)
	copy(witness.Out[:], ciphertext)

	wtns, err := frontend.NewWitness(&witness, ecc.BN254.ScalarField())

	proof, err := groth16.Prove(r1cs, pk, wtns)

	wp, err := frontend.NewWitness(&witness, ecc.BN254.ScalarField(), frontend.PublicOnly())
	err = groth16.Verify(proof, vk, wp)
	return err
}
