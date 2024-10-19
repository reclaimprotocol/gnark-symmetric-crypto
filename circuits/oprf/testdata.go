package oprf

import (
	"crypto/rand"
	"math/big"

	tbn254 "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
	"github.com/consensys/gnark/test"
)

var BN254ScalarField = func() *big.Int { order := tbn254.GetEdwardsCurve().Order; return &order }()

type Proof struct {
	ServerPublicKey twistededwards.Point
	Challenge       *big.Int
	Proof           *big.Int
}

type TestData struct {
	Response   twistededwards.Point
	SecretData *big.Int
	Output     twistededwards.Point
	Mask       *big.Int
	InvMask    *big.Int
	Proof      *Proof
}

func PrepareTestData(assert *test.Assert, secretData string) *OPRFData {
	curve := tbn254.GetEdwardsCurve()
	secretBytes := []byte(secretData)
	if len(secretBytes) > 31*2 {
		panic("secret data too big")
	}

	secretElements := make([]*big.Int, 2)

	if len(secretBytes) > 31 {
		secretElements[0] = new(big.Int).SetBytes(secretBytes[:31])
		secretElements[1] = new(big.Int).SetBytes(secretBytes[31:])
	} else {
		secretElements[0] = new(big.Int).SetBytes(secretBytes)
		secretElements[1] = big.NewInt(0)
	}

	// random mask
	mask, _ := rand.Int(rand.Reader, BN254ScalarField)

	// server secret & public
	sk, _ := rand.Int(rand.Reader, BN254ScalarField)
	serverPublic := &tbn254.PointAffine{}
	serverPublic.ScalarMultiplication(&curve.Base, sk) // G*sk

	H := hashToCurve(secretElements[0].Bytes(), secretElements[1].Bytes()) // H
	assert.True(H.IsOnCurve())

	// mask
	masked := &tbn254.PointAffine{}
	masked.ScalarMultiplication(H, mask) // H*Proof

	// server part
	resp := &tbn254.PointAffine{}
	resp.ScalarMultiplication(masked, sk) // H*Proof*sk

	// output calc
	invR := new(big.Int)
	invR.ModInverse(mask, BN254ScalarField) // Proof^-1

	output := &tbn254.PointAffine{}
	output.ScalarMultiplication(resp, invR) // H *Proof * sk * Proof^-1 = H * sk

	c, r := ProveDLEQ(assert, sk, serverPublic, resp, masked)

	return &OPRFData{
		Response:        OutPointToInPoint(resp),
		SecretData:      [2]frontend.Variable{secretElements[0], secretElements[1]},
		Output:          OutPointToInPoint(output),
		Mask:            mask,
		ServerPublicKey: OutPointToInPoint(serverPublic),
		C:               c,
		S:               r,
	}
}

func ProveDLEQ(assert *test.Assert, x *big.Int, xG, xH, H *tbn254.PointAffine) (*big.Int, *big.Int) {

	// xG = G*x xH = H*x

	curve := tbn254.GetEdwardsCurve()
	base := curve.Base
	// random scalar
	v, err := rand.Int(rand.Reader, BN254ScalarField)
	assert.NoError(err)

	vG := new(tbn254.PointAffine)
	vG.ScalarMultiplication(&base, v) // G*v

	vH := new(tbn254.PointAffine)
	vH.ScalarMultiplication(H, v) // H*v

	challengeHash := hashPoints(&base, vG, vH, H, xH)
	c := new(big.Int).SetBytes(challengeHash)
	// c.Mod(c, scalarField) // ?

	r := new(big.Int).Neg(c) // Proof = -c
	r.Mul(r, x)              // Proof = -c*x
	r.Add(r, v)              // Proof = v - c*x
	r.Mod(r, BN254ScalarField)

	// check Proof in house
	/*
		vG==rG+c(xG)
		vH==rH+c(xH)
	*/
	rg := new(tbn254.PointAffine).ScalarMultiplication(&base, r) // G * Proof = G * (v-c*x)
	chg := new(tbn254.PointAffine).ScalarMultiplication(xG, c)   // G*x*c

	rg.Add(rg, chg) // G * (v-c*x) + G*x*c =G*v − G*c*x + G*c*x = vG
	assert.True(rg.Equal(vG))

	rH := new(tbn254.PointAffine).ScalarMultiplication(H, r)  // H * Proof = H * (v-c*x)
	cH := new(tbn254.PointAffine).ScalarMultiplication(xH, c) // H*x*c

	cH.Add(rH, cH) // H * (v-c*x) + H*x*c =H*v − H*c*x + H*c*x = vH
	assert.True(cH.Equal(vH))

	verifyHash := hashPoints(&base, rg, cH, H, xH)
	verifyNum := new(big.Int).SetBytes(verifyHash)
	assert.Equal(verifyNum, c)

	return c, r
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
		t := d
		if len(d) == 0 {
			t = []byte{0} // otherwise hasher won't pick zero values
		}
		_, err := hasher.Write(t)
		if err != nil {
			panic(err)
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

func hashToCurve(data ...[]byte) *tbn254.PointAffine {
	hashedData := hashBN(data...)
	scalar := new(big.Int).SetBytes(hashedData)
	params := tbn254.GetEdwardsCurve()
	multiplicationResult := &tbn254.PointAffine{}
	multiplicationResult.ScalarMultiplication(&params.Base, scalar)
	return multiplicationResult
}
