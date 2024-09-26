package utils_test

import (
	"crypto/elliptic"
	"crypto/sha256"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark-crypto/hash"
	gnarkeddsa "github.com/consensys/gnark-crypto/signature/eddsa"
	twistededwards2 "github.com/consensys/gnark/std/algebra/native/twistededwards"
	"github.com/consensys/gnark/std/signature/eddsa"
	"gnark-symmetric-crypto/utils"
	"math/big"
	"math/rand"
	"testing"
	"time"

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
	curve := elliptic.P256()
	snarkField, _ := twistededwards2.GetSnarkField(twistededwards.BN254)

	seed := generateRandomSeed(t)
	randomness := rand.New(rand.NewSource(seed))

	// Generate EDDSA key pair
	privKey, err := gnarkeddsa.New(twistededwards.BN254, randomness)

	assert.NoError(err, "unable to generate random key")

	pubKey := privKey.Public()

	t.Logf("priv Key %d", privKey)
	t.Logf("pub Key %d", pubKey)

	secretData := []byte("user:123")

	x, y := HashToCurve(curve, secretData)

	t.Logf("HashToCurve(%s) -> %d, %d", curve, x, y)

	r := new(big.Int).SetInt64(generateRandomSeed(t))

	// Compute mishtiInput = H * r
	mishtiInputX := new(big.Int).Mul(x, r)
	mishtiInputY := new(big.Int).Mul(y, r)

	t.Logf("MishtiInput: X = %s, Y = %s", mishtiInputX.String(), mishtiInputY.String())

	// Prepare mishtiResponse
	mishtiResponse, _ := new(big.Int).SetString("10110291770324934936175892571039775697749083457971239981851098944223339000212", 10)

	// Prepare the message
	msgDataUnpadded := []byte(
		fmt.Sprintf(
			"MishtiInput: X=%s, Y=%s, MishtiResponse: %s",
			mishtiInputX.String(),
			mishtiInputY.String(),
			mishtiResponse.String(),
		),
	)
	t.Logf("msg (size=%d)to sign %s", len(msgDataUnpadded), msgDataUnpadded)
	msgData := make([]byte, len(snarkField.Bytes())+len(msgDataUnpadded))
	copy(msgData[len(msgData)-len(msgDataUnpadded):], msgDataUnpadded)
	t.Logf("msg with padding (size=%d) to sign %s", len(msgData), msgData)

	// Sign the message
	t.Logf("len(PubKey) = %d", len(pubKey.Bytes()))
	_publicKeyBytes := pubKey.Bytes()[:]
	_publicKey := new(eddsa.PublicKey)
	_publicKey.Assign(twistededwards.BN254, _publicKeyBytes)

	t.Logf("_publicKey = %d", _publicKey)

	signatureOf, err := privKey.Sign(msgData, hash.MIMC_BN254.New())
	assert.NoError(err, "signing message")

	checkSig, err := pubKey.Verify(signatureOf, msgData, hash.MIMC_BN254.New())
	assert.NoError(err, "verifying signature")
	assert.True(checkSig, "signature verification failed")

	_signature := new(eddsa.Signature)
	_signature.Assign(twistededwards.BN254, signatureOf)

	// Prepare circuit inputs
	input := utils.NullificationInput{
		Mask:           r,
		Signature:      *_signature,
		PublicKey:      *_publicKey,
		MishtiResponse: []frontend.Variable{mishtiResponse},
		SecretData:     []frontend.Variable{string(secretData)},
	}

	// Create circuit assignment
	assignment := ProcessNullificationCircuit{
		Input: input,
	}

	// Assert that the circuit compiles and runs correctly
	assert.ProverSucceeded(&ProcessNullificationCircuit{}, &assignment)
}

// Elligator2 mapping constants (assuming Curve25519-like parameters)
var (
	A, _ = new(big.Int).SetString("486662", 10) // Curve25519's A parameter
	D, _ = new(big.Int).SetString("1", 10)      // Using 1 for simplicity
)

// HashToCurve hashes data to a point on the elliptic curve using Elligator2 mapping
func HashToCurve(curve elliptic.Curve, data []byte) (x, y *big.Int) {
	// Step 1: Hash the data using a cryptographic hash function (SHA-256)
	hashOf := sha256.Sum256(data)
	u := new(big.Int).SetBytes(hashOf[:])

	// Step 2: Compute Elligator2 mapping
	one := big.NewInt(1)
	uSquared := new(big.Int).Mul(u, u)

	// Compute v = -A / (1 + D * u^2)
	duSquared := new(big.Int).Mul(D, uSquared)
	denominator := new(big.Int).Add(one, duSquared)
	denominator.Mod(denominator, curve.Params().P)
	v := new(big.Int).Neg(A)
	v.Mod(v, curve.Params().P)
	v.Mul(v, new(big.Int).ModInverse(denominator, curve.Params().P))
	v.Mod(v, curve.Params().P)

	// Compute x = v * (1 + u^2) / (1 - u^2)
	numeratorX := new(big.Int).Add(one, uSquared)
	numeratorX.Mul(numeratorX, v)
	denominatorX := new(big.Int).Sub(one, uSquared)
	denominatorX.Mod(denominatorX, curve.Params().P)
	x = new(big.Int).Mul(numeratorX, new(big.Int).ModInverse(denominatorX, curve.Params().P))
	x.Mod(x, curve.Params().P)

	// Compute y numerator and denominator
	numeratorY := new(big.Int).Sub(u, new(big.Int).Mul(x, u))
	numeratorY.Mod(numeratorY, curve.Params().P)
	denominatorY := new(big.Int).Add(one, new(big.Int).Mul(x, v))
	denominatorY.Mod(denominatorY, curve.Params().P)
	y = new(big.Int).Mul(numeratorY, new(big.Int).ModInverse(denominatorY, curve.Params().P))
	y.Mod(y, curve.Params().P)

	return x, y
}

func generateRandomSeed(t *testing.T) int64 {
	seed := time.Now().Unix()
	t.Logf("setting seed in rand %d", seed)
	return seed
}
