package utils

import (
	"crypto/rand"
	"gnark-symmetric-crypto/circuits/toprf"
	"math/big"

	tbn254 "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
)

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

func PrepareTestData(secretData, domainSeparator string) (*toprf.OPRFData, error) {

	req, err := OPRFGenerateRequest(secretData, domainSeparator)
	if err != nil {
		return nil, err
	}

	// server secret
	curve := tbn254.GetEdwardsCurve()
	sk, _ := rand.Int(rand.Reader, TNBCurveOrder)
	serverPublic := &tbn254.PointAffine{}
	serverPublic.ScalarMultiplication(&curve.Base, sk) // G*sk

	threshold := toprf.Threshold
	nodes := threshold + 2

	shares, err := CreateShares(nodes, threshold, sk)
	if err != nil {
		return nil, err
	}

	idxs := PickRandomIndexes(nodes, threshold)

	resps := make([]twistededwards.Point, threshold)
	sharePublicKeys := make([]twistededwards.Point, threshold)
	coefficients := make([]frontend.Variable, threshold)
	cs := make([]frontend.Variable, threshold)
	rs := make([]frontend.Variable, threshold)

	peers := make([]int, len(idxs))
	for i := 0; i < len(idxs); i++ {
		peers[i] = idxs[i] + 1
	}

	for i := 0; i < threshold; i++ {

		idx := idxs[i]

		var resp *OPRFResponse
		resp, err = OPRFEvaluate(shares[idx].PrivateKey, req.MaskedData)
		if err != nil {
			return nil, err
		}

		resps[i] = OutPointToInPoint(resp.Response)
		sharePublicKeys[i] = OutPointToInPoint(shares[idx].PublicKey)
		coefficients[i] = Coeff(peers[i], peers)
		cs[i] = resp.C
		rs[i] = resp.R

	}

	resp, err := OPRFEvaluate(sk, req.MaskedData)
	if err != nil {
		return nil, err
	}

	out, err := OPRFFinalize(serverPublic, req, resp)
	if err != nil {
		return nil, err
	}

	data := &toprf.OPRFData{
		SecretData:      [2]frontend.Variable{req.SecretElements[0], req.SecretElements[1]},
		DomainSeparator: new(big.Int).SetBytes([]byte(domainSeparator)),
		Output:          OutPointToInPoint(out),
		Mask:            req.Mask,
	}

	copy(data.Responses[:], resps)
	copy(data.SharePublicKeys[:], sharePublicKeys)
	copy(data.Coefficients[:], coefficients)
	copy(data.C[:], cs)
	copy(data.R[:], rs)

	return data, nil
}
