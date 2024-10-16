package utils_test

import (
	"crypto/rand"
	"fmt"
	"gnark-symmetric-crypto/utils"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	tbn254 "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
	"github.com/consensys/gnark/test"
)

var scalarField = func() *big.Int { order := tbn254.GetEdwardsCurve().Order; return &order }()

func TestProcessNullification(t *testing.T) {
	assert := test.NewAssert(t)
	testData := prepareTestData(assert)

	circuit := utils.Nullifier{
		Response:        testData.response,
		SecretData:      testData.secretData,
		Nullifier:       testData.nullifier,
		Mask:            testData.mask,
		ServerPublicKey: testData.proof.serverPublicKey,
		Challenge:       testData.proof.challenge,
		Proof:           testData.proof.proof,
	}

	assert.CheckCircuit(&circuit, test.WithCurves(ecc.BN254), test.WithValidAssignment(&circuit))
	cs, _ := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	fmt.Println(cs.GetNbConstraints())
}

func hashToCurve(data []byte) *tbn254.PointAffine {
	hashedData := hashBN(data)
	scalar := new(big.Int).SetBytes(hashedData)
	params := tbn254.GetEdwardsCurve()
	multiplicationResult := &tbn254.PointAffine{}
	multiplicationResult.ScalarMultiplication(&params.Base, scalar)
	return multiplicationResult
}

type proof struct {
	serverPublicKey twistededwards.Point
	challenge       *big.Int
	proof           *big.Int
}

type testData struct {
	response   twistededwards.Point
	secretData *big.Int
	nullifier  twistededwards.Point
	mask       *big.Int
	invMask    *big.Int
	proof      *proof
}

func prepareTestData(assert *test.Assert) testData {
	curve := tbn254.GetEdwardsCurve()
	secretData := (&big.Int{}).SetBytes([]byte("alex@reclaimprotocol.org"))

	// random mask
	mask, _ := rand.Int(rand.Reader, scalarField)

	// server secret & public
	sk, _ := rand.Int(rand.Reader, scalarField)
	serverPublic := &tbn254.PointAffine{}
	serverPublic.ScalarMultiplication(&curve.Base, sk) // G*sk

	H := hashToCurve(secretData.Bytes()) // H
	assert.True(H.IsOnCurve())

	// mask
	masked := &tbn254.PointAffine{}
	masked.ScalarMultiplication(H, mask) // H*proof

	// server part
	resp := &tbn254.PointAffine{}
	resp.ScalarMultiplication(masked, sk) // H*proof*sk

	// nullifier calc
	invR := new(big.Int)
	invR.ModInverse(mask, scalarField) // proof^-1

	nullifier := &tbn254.PointAffine{}
	nullifier.ScalarMultiplication(resp, invR) // H *proof * sk * proof^-1 = H * sk

	c, r := ProveDLEQ(assert, sk, serverPublic, resp, masked)

	return testData{
		response:   OutPointToInPoint(resp),
		secretData: secretData,
		nullifier:  OutPointToInPoint(nullifier),
		mask:       mask,
		invMask:    invR,
		proof: &proof{
			serverPublicKey: OutPointToInPoint(serverPublic),
			challenge:       c,
			proof:           r,
		},
	}
}

func OutPointToInPoint(point *tbn254.PointAffine) twistededwards.Point {
	res := twistededwards.Point{
		X: point.X.BigInt(&big.Int{}),
		Y: point.Y.BigInt(&big.Int{}),
	}
	return res
}

func hashBN(data ...[]byte) []byte {
	hasher := hash.MIMC_BN254.New()
	for _, d := range data {
		_, err := hasher.Write(d)
		if err != nil {
			r := new(big.Int).SetBytes(d)
			r.Mod(r, scalarField)
			_, err = hasher.Write(r.Bytes())
			if err != nil {
				panic(err)
			}
		}
	}
	return hasher.Sum(nil)
}

func hashPoints(data ...*tbn254.PointAffine) []byte {
	hasher := hash.MIMC_BN254.New()
	for _, p := range data {
		x := p.X.BigInt(new(big.Int))
		y := p.Y.BigInt(new(big.Int))
		_, err := hasher.Write(x.Bytes())
		if err != nil {
			panic(err)
		}
		_, err = hasher.Write(y.Bytes())
		if err != nil {
			panic(err)
		}
	}
	return hasher.Sum(nil)
}

func TestMaskUnmask(t *testing.T) {
	assert := test.NewAssert(t)
	curve := tbn254.GetEdwardsCurve()
	data := &tbn254.PointAffine{}
	base := curve.Base
	data.ScalarMultiplication(&base, big.NewInt(12345)) // just dummy data

	// random scalar
	r, err := rand.Int(rand.Reader, scalarField)
	assert.NoError(err)

	blinded := &tbn254.PointAffine{}
	blinded.ScalarMultiplication(data, r)

	invR := &big.Int{}
	invR.ModInverse(r, scalarField)
	deblinded := &tbn254.PointAffine{}
	deblinded.ScalarMultiplication(blinded, invR)
	fmt.Println(r, invR)
	assert.True(deblinded.Equal(data))
}

func ProveDLEQ(assert *test.Assert, x *big.Int, xG, xH, H *tbn254.PointAffine) (*big.Int, *big.Int) {

	// xG = G*x xH = H*x

	curve := tbn254.GetEdwardsCurve()
	base := curve.Base
	// random scalar
	v, err := rand.Int(rand.Reader, scalarField)
	assert.NoError(err)

	vG := new(tbn254.PointAffine)
	vG.ScalarMultiplication(&base, v) // G*v

	vH := new(tbn254.PointAffine)
	vH.ScalarMultiplication(H, v) // H*v

	challengeHash := hashPoints(&base, vG, vH, H, xH)
	c := new(big.Int).SetBytes(challengeHash)
	// c.Mod(c, scalarField) // ?

	r := new(big.Int).Neg(c) // proof = -c
	r.Mul(r, x)              // proof = -c*x
	r.Add(r, v)              // proof = v - c*x
	r.Mod(r, scalarField)

	// check proof in house
	/*
		vG==rG+c(xG)
		vH==rH+c(xH)
	*/
	rg := new(tbn254.PointAffine).ScalarMultiplication(&base, r) // G * proof = G * (v-c*x)
	chg := new(tbn254.PointAffine).ScalarMultiplication(xG, c)   // G*x*c

	rg.Add(rg, chg) // G * (v-c*x) + G*x*c =G*v − G*c*x + G*c*x = vG
	assert.True(rg.Equal(vG))

	rH := new(tbn254.PointAffine).ScalarMultiplication(H, r)  // H * proof = H * (v-c*x)
	cH := new(tbn254.PointAffine).ScalarMultiplication(xH, c) // H*x*c

	cH.Add(rH, cH) // H * (v-c*x) + H*x*c =H*v − H*c*x + H*c*x = vH
	assert.True(cH.Equal(vH))

	verifyHash := hashPoints(&base, rg, cH, H, xH)
	verifyNum := new(big.Int).SetBytes(verifyHash)
	assert.Equal(verifyNum, c)

	return c, r
}

func TestArithBN(t *testing.T) {
	assert := test.NewAssert(t)

	curveOrder := ecc.BN254.ScalarField()

	// random element
	x, _ := rand.Int(rand.Reader, curveOrder)

	// random element
	y, _ := rand.Int(rand.Reader, curveOrder)

	t1 := &bn254.G1Affine{}
	t1.ScalarMultiplicationBase(x) // G*x

	t2 := &bn254.G1Affine{}
	t2.ScalarMultiplicationBase(y) // G*y

	t3 := &bn254.G1Affine{}
	t3.Add(t1, t2) // G*x + G*y

	z := new(big.Int)
	z.Add(x, y)
	z.Mod(z, curveOrder)

	t4 := &bn254.G1Affine{}
	t4.ScalarMultiplicationBase(z)
	assert.True(t4.Equal(t3))

	w := new(big.Int)
	w.Neg(y)
	w.Mod(w, curveOrder)
	t5 := &bn254.G1Affine{}
	t5.ScalarMultiplicationBase(w) // G* -y

	t6 := &bn254.G1Affine{}
	t6.Add(t3, t5) // G* -y + G*x + G*y = G*x

	assert.True(t6.Equal(t1))
}

func TestArithBabyJub(t *testing.T) {
	assert := test.NewAssert(t)

	curveOrder := tbn254.GetEdwardsCurve().Order
	base := tbn254.GetEdwardsCurve().Base

	// random element
	x, _ := rand.Int(rand.Reader, &curveOrder)

	// random element
	y, _ := rand.Int(rand.Reader, &curveOrder)

	t1 := &tbn254.PointAffine{}
	t1.ScalarMultiplication(&base, x) // G*x

	t2 := &tbn254.PointAffine{}
	t2.ScalarMultiplication(&base, y) // G*y

	t3 := &tbn254.PointAffine{}
	t3.Add(t1, t2) // G*x + G*y

	z := new(big.Int)
	z.Add(x, y) // x+y
	z.Mod(z, &curveOrder)

	t4 := &tbn254.PointAffine{}
	t4.ScalarMultiplication(&base, z) // G * (x+y)
	assert.True(t4.Equal(t3))

	w := new(big.Int)
	w.Neg(y) // -y
	w.Mod(w, &curveOrder)
	t5 := &tbn254.PointAffine{}
	t5.ScalarMultiplication(&base, w) // G* -y

	t6 := &tbn254.PointAffine{}
	t6.Add(t3, t5) // G* -y + G*x + G*y = G*x

	assert.True(t6.Equal(t1))
}
