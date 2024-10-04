package utils_test

import (
	"fmt"
	"gnark-symmetric-crypto/utils"
	"math/big"
	"math/rand"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark-crypto/hash"
	gnarkeddsa "github.com/consensys/gnark-crypto/signature/eddsa"
	twistededwards2 "github.com/consensys/gnark/std/algebra/native/twistededwards"
	"github.com/consensys/gnark/std/signature/eddsa"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type ProcessNullificationCircuit struct {
	Input utils.NullificationInput
}

func (circuit *ProcessNullificationCircuit) Define(api frontend.API) error {
	return utils.ProcessNullification(api, circuit.Input)
}

func TestProcessNullification(t *testing.T) {
	assert := test.NewAssert(t)
	curve, err := twistededwards2.GetCurveParams(twistededwards.BN254)
	assert.NoError(err, "unable to get curve parameters")

	seed := generateRandomSeed(t)
	randomness := rand.New(rand.NewSource(seed))

	// Generate EDDSA key pair
	privKey, err := gnarkeddsa.New(twistededwards.BN254, randomness)
	assert.NoError(err, "unable to generate random key")
	pubKey := privKey.Public()

	secretData := []byte("user:123")

	x, y := HashToCurve(*curve, secretData)
	//t.Logf("x = %v, y = %v", x, y)
	r := new(big.Int).SetInt64(generateRandomSeed(t))

	// Compute mishtiInput = H * r
	mishtiInputX := new(big.Int).Mul(x, r)
	mishtiInputY := new(big.Int).Mul(y, r)

	// Prepare mishtiResponse
	mishtiResponse, _ := new(big.Int).SetString("10110291770324934936175892571039775697749083457971239981851098944223339000212", 10)

	// Prepare the message
	msgDataUnpadded := []byte(
		fmt.Sprintf(
			"%s,%s,%s",
			mishtiInputX.String(),
			mishtiInputY.String(),
			mishtiResponse.String(),
		),
	)

	t.Logf("Message v: %s", msgDataUnpadded)
	_publicKeyBytes := pubKey.Bytes()[:]
	_publicKey := new(eddsa.PublicKey)
	_publicKey.Assign(twistededwards.BN254, _publicKeyBytes)

	hashV, err := utils.HashBN254(msgDataUnpadded)
	assert.NoError(err, "unable to hash message")
	t.Logf("Hash v: %x", hashV)
	signatureOf, err := privKey.Sign(hashV, hash.MIMC_BN254.New())
	assert.NoError(err, "signing message")

	checkSig, err := pubKey.Verify(signatureOf, hashV, hash.MIMC_BN254.New())
	assert.NoError(err, "verifying signature")
	assert.True(checkSig, "signature verification failed")

	_signature := new(eddsa.Signature)
	_signature.Assign(twistededwards.BN254, signatureOf)

	// Prepare circuit inputs
	input := utils.NullificationInput{
		Mask:           r,
		Signature:      *_signature,
		PublicKey:      *_publicKey,
		SecretData:     secretData,
		MishtiResponse: mishtiResponse,
	}

	// Create circuit assignment
	assignment := ProcessNullificationCircuit{
		Input: input,
	}

	// Assert that the circuit compiles and runs correctly
	assert.ProverSucceeded(&ProcessNullificationCircuit{}, &assignment)
}

// HashToCurve hashes data to a point on the elliptic curve using Elligator2 mapping
func HashToCurve(curve twistededwards2.CurveParams, data []byte) (x, y *big.Int) {
	hashOf, _ := utils.HashBN254(data)
	u := new(big.Int).SetBytes(hashOf)

	// Constants
	A := curve.A
	D := curve.D

	// Step 2: Compute Elligator2 mapping
	one := big.NewInt(1)
	uSquared := new(big.Int).Mul(u, u)

	// Compute v = -A / (1 + D * u^2)
	denominator := new(big.Int).Add(one, new(big.Int).Mul(D, uSquared))
	denominator.Mod(denominator, curve.Order)

	v := new(big.Int).Neg(A)
	v.Mod(v, curve.Order)
	v.Mul(v, new(big.Int).ModInverse(denominator, curve.Order))
	// v.Mul(v, denominator)
	v.Mod(v, curve.Order)

	// Compute x = v * (1 + u^2) / (1 - u^2)
	numeratorX := new(big.Int).Add(one, uSquared)
	numeratorX.Mul(numeratorX, v)
	denominatorX := new(big.Int).Sub(one, uSquared)
	denominatorX.Mod(denominatorX, curve.Order)
	x = new(big.Int).Mul(numeratorX, new(big.Int).ModInverse(denominatorX, curve.Order))
	// x = new(big.Int).Mul(numeratorX, denominatorX)
	x.Mod(x, curve.Order)

	// Compute y numerator and denominator
	numeratorY := new(big.Int).Sub(u, new(big.Int).Mul(x, u))
	numeratorY.Mod(numeratorY, curve.Order)
	denominatorY := new(big.Int).Add(one, new(big.Int).Mul(x, v))
	denominatorY.Mod(denominatorY, curve.Order)
	// y = new(big.Int).Mul(numeratorY, denominatorY)
	y = new(big.Int).Mul(numeratorY, new(big.Int).ModInverse(denominatorY, curve.Order))
	y.Mod(y, curve.Order)

	return x, y
}

func generateRandomSeed(t *testing.T) int64 {
	seed := time.Now().Unix()
	//t.Logf("setting seed in rand %d", seed)
	return seed
}
