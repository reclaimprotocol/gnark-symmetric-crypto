package oprf

import (
	"crypto/rand"
	"math/big"

	tbn254 "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
)

func ProveDLEQ(x *big.Int, xG, xH, H *tbn254.PointAffine) (*big.Int, *big.Int, error) {

	// xG = G*x xH = H*x

	curve := tbn254.GetEdwardsCurve()
	base := curve.Base
	// random scalar
	v, err := rand.Int(rand.Reader, BN254ScalarField)
	if err != nil {
		return nil, nil, err
	}

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
	/*rg := new(tbn254.PointAffine).ScalarMultiplication(&base, r) // G * Proof = G * (v-c*x)
	chg := new(tbn254.PointAffine).ScalarMultiplication(xG, c)   // G*x*c

	rg.Add(rg, chg) // G * (v-c*x) + G*x*c =G*v − G*c*x + G*c*x = vG
	assert.True(rg.Equal(vG))

	rH := new(tbn254.PointAffine).ScalarMultiplication(H, r)  // H * Proof = H * (v-c*x)
	cH := new(tbn254.PointAffine).ScalarMultiplication(xH, c) // H*x*c

	cH.Add(rH, cH) // H * (v-c*x) + H*x*c =H*v − H*c*x + H*c*x = vH
	assert.True(cH.Equal(vH))

	verifyHash := hashPoints(&base, rg, cH, H, xH)
	verifyNum := new(big.Int).SetBytes(verifyHash)
	assert.Equal(verifyNum, c)*/

	return c, r, nil
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
