package oprf

import (
	"crypto/rand"
	"gnark-symmetric-crypto/utils"
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

func PrepareTestData(secretData, domainSeparator string) (*OPRFData, error) {

	req, err := utils.GenerateOPRFRequest(secretData, domainSeparator)
	if err != nil {
		return nil, err
	}

	// server secret
	curve := tbn254.GetEdwardsCurve()
	sk, _ := rand.Int(rand.Reader, TNBCurveOrder)
	serverPublic := &tbn254.PointAffine{}
	serverPublic.ScalarMultiplication(&curve.Base, sk) // G*sk

	resp, err := utils.OPRF(sk, req.MaskedData)
	if err != nil {
		return nil, err
	}

	out, err := utils.ProcessOPRFResponse(serverPublic, req, resp)
	if err != nil {
		return nil, err
	}

	return &OPRFData{
		Response:        OutPointToInPoint(resp.Response),
		SecretData:      [2]frontend.Variable{req.SecretElements[0], req.SecretElements[1]},
		DomainSeparator: new(big.Int).SetBytes([]byte(domainSeparator)),
		Output:          OutPointToInPoint(out),
		Mask:            req.Mask,
		ServerPublicKey: OutPointToInPoint(serverPublic),
		C:               resp.C,
		S:               resp.S,
	}, nil
}
