package utils_test

import (
	"crypto/rand"
	"fmt"
	"gnark-symmetric-crypto/utils"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	tbn254 "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	"github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark-crypto/signature"
	gnarkeddsa "github.com/consensys/gnark-crypto/signature/eddsa"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	twistededwards2 "github.com/consensys/gnark/std/algebra/native/twistededwards"
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

	input := utils.NullificationInput{
		Mask:       testData.r,
		SecretData: testData.secretData,
		Response: twistededwards2.Point{
			X: H.X.BigInt(&big.Int{}),
			Y: H.Y.BigInt(&big.Int{}),
		},
		Nullifier: twistededwards2.Point{
			X: H.X.BigInt(&big.Int{}),
			Y: H.Y.BigInt(&big.Int{}),
		},
	}

	assignment := ProcessNullificationCircuit{
		Input: input,
	}

	assert.CheckCircuit(&ProcessNullificationCircuit{input}, test.WithCurves(ecc.BN254), test.WithValidAssignment(&assignment))
	cs, _ := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &assignment)
	fmt.Println(cs.GetNbConstraints())
}

func hashToCurve(data []byte) tbn254.PointAffine {
	hashedData := hashBN(data)
	scalar := new(big.Int).SetBytes(hashedData)
	params := tbn254.GetEdwardsCurve()
	var multiplicationResult tbn254.PointAffine
	multiplicationResult.ScalarMultiplication(&params.Base, scalar)
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

func TestMaskUnmask(t *testing.T) {
	assert := test.NewAssert(t)
	curve := tbn254.GetEdwardsCurve()
	data := &tbn254.PointAffine{}
	base := curve.Base
	data.ScalarMultiplication(&base, big.NewInt(12345)) // just dummy data

	// random scalar
	r, err := rand.Int(rand.Reader, &curve.Order)
	assert.NoError(err)

	blinded := &tbn254.PointAffine{}
	blinded.ScalarMultiplication(data, r)

	invR := r.ModInverse(r, &curve.Order)
	deblinded := &tbn254.PointAffine{}
	deblinded.ScalarMultiplication(blinded, invR)

	assert.True(deblinded.Equal(data))
}

// Decompose decomposes the input into res as integers of width nbBits. It
// errors if the decomposition does not fit into res or if res is uninitialized.
//
// The following holds
//
//	input = \sum_{i=0}^{len(res)} res[i] * 2^{nbBits * i}
func Decompose(input *big.Int, nbBits uint, res []*big.Int) error {
	// limb modulus
	if input.BitLen() > len(res)*int(nbBits) {
		return fmt.Errorf("decomposed integer does not fit into res")
	}
	for _, r := range res {
		if r == nil {
			return fmt.Errorf("result slice element uninitialized")
		}
	}
	base := new(big.Int).Lsh(big.NewInt(1), nbBits)
	tmp := new(big.Int).Set(input)
	for i := 0; i < len(res); i++ {
		res[i].Mod(tmp, base)
		tmp.Rsh(tmp, nbBits)
	}
	return nil
}
