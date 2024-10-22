package utils

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	"github.com/consensys/gnark-crypto/hash"
)

var TNBCurveOrder = func() *big.Int { order := twistededwards.GetEdwardsCurve().Order; return &order }()

type OPRFRequest struct {
	Mask           *big.Int `json:"mask"`
	MaskedData     *twistededwards.PointAffine
	SecretElements [2]*big.Int
}

type OPRFResponse struct {
	Response *twistededwards.PointAffine
	C        *big.Int
	S        *big.Int
}

func GenerateOPRFRequest(secretData, domainSeparator string) (*OPRFRequest, error) {
	secretBytes := []byte(secretData)
	if len(secretBytes) > 31*2 {
		return nil, errors.New("secret data too big")
	}
	domainBytes := []byte(domainSeparator)
	if len(domainBytes) > 31 {
		return nil, errors.New("domain separator too big")
	}

	var secretElements [2]*big.Int

	if len(secretBytes) > 31 {
		secretElements[0] = new(big.Int).SetBytes(secretBytes[:31])
		secretElements[1] = new(big.Int).SetBytes(secretBytes[31:])
	} else {
		secretElements[0] = new(big.Int).SetBytes(secretBytes)
		secretElements[1] = big.NewInt(0)
	}

	H := HashToCurve(secretElements[0].Bytes(), secretElements[1].Bytes(), domainBytes) // H
	if !H.IsOnCurve() {
		return nil, fmt.Errorf("point is not on curve")
	}

	// random mask
	mask, err := rand.Int(rand.Reader, TNBCurveOrder)
	if err != nil {
		return nil, err
	}

	masked := &twistededwards.PointAffine{}
	masked.ScalarMultiplication(H, mask) // H*mask

	return &OPRFRequest{
		Mask:           mask,
		MaskedData:     masked,
		SecretElements: secretElements,
	}, nil
}

func OPRF(serverPrivate *big.Int, request *twistededwards.PointAffine) (*OPRFResponse, error) {
	curve := twistededwards.GetEdwardsCurve()
	resp := &twistededwards.PointAffine{}
	resp.ScalarMultiplication(request, serverPrivate) // H*mask*sk

	serverPublic := &twistededwards.PointAffine{}
	serverPublic.ScalarMultiplication(&curve.Base, serverPrivate) // G*sk

	c, r, err := ProveDLEQ(serverPrivate, serverPublic, resp, request)
	if err != nil {
		return nil, err
	}
	return &OPRFResponse{
		Response: resp,
		C:        c,
		S:        r,
	}, nil
}

func ProcessOPRFResponse(serverPublic *twistededwards.PointAffine, request *OPRFRequest, response *OPRFResponse) (*twistededwards.PointAffine, error) {
	// output calc
	invR := new(big.Int)
	invR.ModInverse(request.Mask, TNBCurveOrder) // mask^-1

	if !VerifyDLEQ(response.C, response.S, serverPublic, response.Response, request.MaskedData) {
		return nil, errors.New("DLEQ proof is invalid")
	}

	output := &twistededwards.PointAffine{}
	output.ScalarMultiplication(response.Response, invR) // H *mask * sk * mask^-1 = H * sk
	return output, nil
}

func ProveDLEQ(x *big.Int, xG, xH, H *twistededwards.PointAffine) (*big.Int, *big.Int, error) {

	// xG = G*x, xH = H*x

	curve := twistededwards.GetEdwardsCurve()
	base := curve.Base

	// random scalar
	v, err := rand.Int(rand.Reader, TNBCurveOrder)
	if err != nil {
		return nil, nil, err
	}

	vG := new(twistededwards.PointAffine)
	vG.ScalarMultiplication(&base, v) // G*v

	vH := new(twistededwards.PointAffine)
	vH.ScalarMultiplication(H, v) // H*v

	challengeHash := HashPointsToScalar(&base, xG, vG, vH, H, xH)
	c := new(big.Int).SetBytes(challengeHash)
	// c.Mod(c, scalarField) // ?

	r := new(big.Int).Neg(c) // -c
	r.Mul(r, x)              // -c*x
	r.Add(r, v)              // v - c*x
	r.Mod(r, TNBCurveOrder)

	return c, r, nil
}

func VerifyDLEQ(c, r *big.Int, xG, xH, H *twistededwards.PointAffine) bool {
	curve := twistededwards.GetEdwardsCurve()
	base := curve.Base

	/*
		vG==rG+c(xG)
		vH==rH+c(xH)
	*/
	rg := new(twistededwards.PointAffine).ScalarMultiplication(&base, r) // G * Mask = G * (v-c*x)
	chg := new(twistededwards.PointAffine).ScalarMultiplication(xG, c)   // G*x*c

	vG := rg.Add(rg, chg) // G * (v-c*x) + G*x*c =G*v − G*c*x + G*c*x = vG

	rH := new(twistededwards.PointAffine).ScalarMultiplication(H, r)  // H * Mask = H * (v-c*x)
	cH := new(twistededwards.PointAffine).ScalarMultiplication(xH, c) // H*x*c

	vH := cH.Add(rH, cH) // H * (v-c*x) + H*x*c =H*v − H*c*x + H*c*x = vH

	verifyHash := HashPointsToScalar(&base, xG, vG, vH, H, xH)
	verifyNum := new(big.Int).SetBytes(verifyHash)
	return verifyNum.Cmp(c) == 0
}

func hashToScalar(data ...[]byte) []byte {
	hasher := hash.MIMC_BN254.New()
	for _, d := range data {
		t := d
		if len(d) == 0 {
			t = []byte{0} // otherwise hasher won't pick nil values
		}
		_, err := hasher.Write(t)
		if err != nil {
			panic(err)
		}
	}
	return hasher.Sum(nil)
}

func HashPointsToScalar(data ...*twistededwards.PointAffine) []byte {
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

func HashToCurve(data ...[]byte) *twistededwards.PointAffine {
	hashedData := hashToScalar(data...)
	scalar := new(big.Int).SetBytes(hashedData)
	params := twistededwards.GetEdwardsCurve()
	multiplicationResult := &twistededwards.PointAffine{}
	multiplicationResult.ScalarMultiplication(&params.Base, scalar)
	return multiplicationResult
}
