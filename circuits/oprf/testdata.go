package oprf

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"

	tbn254 "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
)

var TNBCurveOrder = func() *big.Int { order := tbn254.GetEdwardsCurve().Order; return &order }()

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

type OPRFRequest struct {
	SecretElements  [2]*big.Int
	Mask            *big.Int
	MaskedData      *tbn254.PointAffine
	DomainSeparator *big.Int
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

	H := hashToCurve(secretElements[0].Bytes(), secretElements[1].Bytes(), domainBytes) // H
	if !H.IsOnCurve() {
		return nil, fmt.Errorf("point is not on curve")
	}

	// random mask
	mask, err := rand.Int(rand.Reader, TNBCurveOrder)
	if err != nil {
		return nil, err
	}

	// mask
	masked := &tbn254.PointAffine{}
	masked.ScalarMultiplication(H, mask) // H*mask

	return &OPRFRequest{
		SecretElements:  secretElements,
		Mask:            mask,
		MaskedData:      masked,
		DomainSeparator: new(big.Int).SetBytes(domainBytes),
	}, nil
}

func PrepareTestData(secretData, domainSeparator string) (*OPRFData, error) {
	curve := tbn254.GetEdwardsCurve()

	req, err := GenerateOPRFRequest(secretData, domainSeparator)
	if err != nil {
		return nil, err
	}

	// server secret & public
	sk, _ := rand.Int(rand.Reader, TNBCurveOrder)
	serverPublic := &tbn254.PointAffine{}
	serverPublic.ScalarMultiplication(&curve.Base, sk) // G*sk

	// server part
	resp := &tbn254.PointAffine{}
	resp.ScalarMultiplication(req.MaskedData, sk) // H*mask*sk

	// output calc
	invR := new(big.Int)
	invR.ModInverse(req.Mask, TNBCurveOrder) // mask^-1

	output := &tbn254.PointAffine{}
	output.ScalarMultiplication(resp, invR) // H *mask * sk * mask^-1 = H * sk

	c, r, err := ProveDLEQ(sk, serverPublic, resp, req.MaskedData)
	if err != nil {
		return nil, err
	}

	return &OPRFData{
		Response:        OutPointToInPoint(resp),
		SecretData:      [2]frontend.Variable{req.SecretElements[0], req.SecretElements[1]},
		DomainSeparator: req.DomainSeparator,
		Output:          OutPointToInPoint(output),
		Mask:            req.Mask,
		ServerPublicKey: OutPointToInPoint(serverPublic),
		C:               c,
		S:               r,
	}, nil
}
