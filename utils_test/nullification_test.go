package utils_test

import (
	"crypto/rand"
	"fmt"
	"gnark-symmetric-crypto/utils"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	tbn254 "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	"github.com/consensys/gnark-crypto/signature"
	twistededwards2 "github.com/consensys/gnark/std/algebra/native/twistededwards"

	"github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark-crypto/hash"
	gnarkeddsa "github.com/consensys/gnark-crypto/signature/eddsa"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/signature/eddsa"
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
	testData := prepareTestData()

	H := hashToCurve(testData.secretData.Bytes())
	assert.Equal(true, H.IsOnCurve())

	// Compute mishtiInput = H * r
	var mishtiInput tbn254.PointAffine
	mishtiInput.ScalarMultiplication(&H, testData.r)

	// mishtiInput := H.ScalarMultiplication(&H, testData.r)
	assert.Equal(true, mishtiInput.IsOnCurve())

	hashedMsg := hashBN(
		new(big.Int).SetBytes(mishtiInput.X.Marshal()).Bytes(),
		new(big.Int).SetBytes(mishtiInput.Y.Marshal()).Bytes(),
		testData.mishtiResponse.Bytes(),
	)

	signatureOf := signAndVerify(assert, hashedMsg, testData.privateKey, testData.publicKey)

	nullifier := new(big.Int).Mul(testData.mishtiResponse, new(big.Int).ModInverse(testData.r, scalarField))
	nullifier.Mod(nullifier, scalarField)

	input := utils.NullificationInput{
		Mask:           testData.r,
		Signature:      castToEddsaSignature(signatureOf),
		PublicKey:      castToEddsaPublicKey(testData.publicKey),
		SecretData:     testData.secretData,
		MishtiResponse: testData.mishtiResponse,
		Nullifier:      nullifier,
	}

	assignment := ProcessNullificationCircuit{
		Input: input,
	}

	assert.CheckCircuit(&ProcessNullificationCircuit{}, test.WithCurves(ecc.BN254), test.WithValidAssignment(&assignment))
}

func hashToCurve(data []byte) tbn254.PointAffine {
	hashedData := hashBN(data)
	scalar := new(big.Int).SetBytes(hashedData)
	curve := twistededwards.BN254
	params, _ := twistededwards2.GetCurveParams(curve)
	var point, multiplicationResult tbn254.PointAffine
	point.X.SetBigInt(params.Base[0])
	point.Y.SetBigInt(params.Base[1])
	multiplicationResult.ScalarMultiplication(&point, scalar)
	return multiplicationResult
}

type testData struct {
	privateKey     signature.Signer
	publicKey      signature.PublicKey
	secretData     *big.Int
	mishtiResponse *big.Int
	r              *big.Int
}

func prepareTestData() testData {
	mishtiResponse, _ := new(big.Int).SetString("10110291770324934936175892571039775697749083457971239981851098944223339000212", 10)
	var t tbn254.PointAffine
	_, err := t.SetBytes(mishtiResponse.Bytes())
	if err != nil {
		panic(err)
	}
	fmt.Println(t.IsOnCurve())
	t.Marshal()

	privateKey, _ := gnarkeddsa.New(twistededwards.BN254, rand.Reader)
	pubKey := privateKey.Public()

	secretData, _ := new(big.Int).SetString("123", 10)
	r, _ := rand.Int(rand.Reader, scalarField)
	return testData{
		privateKey:     privateKey,
		publicKey:      pubKey,
		secretData:     secretData,
		mishtiResponse: mishtiResponse,
		r:              r,
	}
}

func castToEddsaSignature(signatureOf []byte) eddsa.Signature {
	_signature := new(eddsa.Signature)
	_signature.Assign(twistededwards.BN254, signatureOf)
	return *_signature
}

func castToEddsaPublicKey(pubKey signature.PublicKey) eddsa.PublicKey {
	_publicKeyBytes := pubKey.Bytes()
	_publicKey := new(eddsa.PublicKey)
	_publicKey.Assign(twistededwards.BN254, _publicKeyBytes)
	return *_publicKey
}

func hashBN(data ...[]byte) []byte {
	hasher := hash.MIMC_BN254.New()
	for _, d := range data {
		hasher.Write(d)
	}
	return hasher.Sum(nil)
}

func signAndVerify(assert *test.Assert, message []byte, privateKey signature.Signer, publicKey signature.PublicKey) []byte {
	signatureOf, err := privateKey.Sign(message, hash.MIMC_BN254.New())
	assert.NoError(err, "signing message")
	checkSig, err := publicKey.Verify(signatureOf, message, hash.MIMC_BN254.New())
	assert.NoError(err, "verifying signature")
	assert.True(checkSig, "signature verification failed")
	return signatureOf
}
