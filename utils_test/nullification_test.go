package utils_test

import (
	"fmt"
	"gnark-symmetric-crypto/utils"
	"math/big"
	"math/rand"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"

	"github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark-crypto/hash"
	gnarkeddsa "github.com/consensys/gnark-crypto/signature/eddsa"
	twistededwards2 "github.com/consensys/gnark/std/algebra/native/twistededwards"
	"github.com/consensys/gnark/std/signature/eddsa"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

var scalarField = ecc.BN254.ScalarField()

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

	seed := generateRandomSeed()
	randomness := rand.New(rand.NewSource(seed))

	privKey, err := gnarkeddsa.New(twistededwards.BN254, randomness)
	assert.NoError(err, "unable to generate random key")
	pubKey := privKey.Public()

	secretData := []byte("user:123")

	x, y := HashToCurve(*curve, secretData)
	r := new(big.Int).SetInt64(generateRandomSeed())

	// Compute mishtiInput = H * r
	mishtiInputX := new(big.Int).Mul(x, r)
	mishtiInputX.Mod(mishtiInputX, scalarField)
	mishtiInputY := new(big.Int).Mul(y, r)
	mishtiInputY.Mod(mishtiInputY, scalarField)

	mishtiResponse, _ := new(big.Int).SetString("10110291770324934936175892571039775697749083457971239981851098944223339000212", 10)

	msgDataUnpadded := []byte(
		fmt.Sprintf(
			"%s,%s,%s",
			mishtiInputX.String(),
			mishtiInputY.String(),
			mishtiResponse.String(),
		),
	)
	paddedMsg := utils.PadMsg(msgDataUnpadded, 32, scalarField)

	signatureOf, err := privKey.Sign(paddedMsg, hash.MIMC_BN254.New())
	assert.NoError(err, "signing message")

	checkSig, err := pubKey.Verify(signatureOf, paddedMsg, hash.MIMC_BN254.New())
	assert.NoError(err, "verifying signature")
	assert.True(checkSig, "signature verification failed")

	_signature := new(eddsa.Signature)
	_signature.Assign(twistededwards.BN254, signatureOf)
	_publicKeyBytes := pubKey.Bytes()
	_publicKey := new(eddsa.PublicKey)
	_publicKey.Assign(twistededwards.BN254, _publicKeyBytes)

	input := utils.NullificationInput{
		Mask:           r,
		Signature:      *_signature,
		PublicKey:      *_publicKey,
		SecretData:     secretData,
		MishtiResponse: mishtiResponse,
	}

	assignment := ProcessNullificationCircuit{
		Input: input,
	}

	assert.CheckCircuit(&ProcessNullificationCircuit{}, test.WithCurves(ecc.BN254), test.WithValidAssignment(&assignment))
}

func HashToCurve(curve twistededwards2.CurveParams, data []byte) (x, y *big.Int) {
	hasher := hash.Hash.New(hash.MIMC_BN254)
	paddedData := utils.PadMsg(data, 32, scalarField)
	hasher.Write(paddedData)
	u := new(big.Int).SetBytes(hasher.Sum(nil))

	// Constants
	A := curve.A
	D := curve.D
	one := big.NewInt(1)
	uSquared := new(big.Int).Mul(u, u)

	// Compute v = -A / (1 + D * u^2)
	denominator := new(big.Int).Add(one, new(big.Int).Mul(D, uSquared))
	denominator.Mod(denominator, scalarField)

	v := new(big.Int).Neg(A)
	v.Mod(v, scalarField)
	v.Mul(v, new(big.Int).ModInverse(denominator, scalarField))
	v.Mod(v, scalarField)

	// Compute x = v * (1 + u^2) / (1 - u^2)
	numeratorX := new(big.Int).Add(one, uSquared)
	numeratorX.Mul(numeratorX, v)
	numeratorX.Mod(numeratorX, scalarField)
	denominatorX := new(big.Int).Sub(one, uSquared)
	denominatorX.Mod(denominatorX, scalarField)
	x = new(big.Int).Mul(numeratorX, new(big.Int).ModInverse(denominatorX, scalarField))
	x.Mod(x, scalarField)

	// Compute y numerator and denominator
	numeratorY := new(big.Int).Sub(u, new(big.Int).Mul(x, u))
	numeratorY.Mod(numeratorY, scalarField)
	denominatorY := new(big.Int).Add(one, new(big.Int).Mul(x, v))
	denominatorY.Mod(denominatorY, scalarField)

	// y = new(big.Int).Mul(numeratorY, denominatorY)
	y = new(big.Int).Mul(numeratorY, new(big.Int).ModInverse(denominatorY, scalarField))
	y.Mod(y, scalarField)

	return x, y
}

func generateRandomSeed() int64 {
	seed := time.Now().Unix()
	return seed
}
