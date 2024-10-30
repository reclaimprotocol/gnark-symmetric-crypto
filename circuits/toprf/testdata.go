package toprf

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

	req, err := utils.OPRFGenerateRequest(secretData, domainSeparator)
	if err != nil {
		return nil, err
	}

	// server secret
	curve := tbn254.GetEdwardsCurve()
	sk, _ := rand.Int(rand.Reader, TNBCurveOrder)
	serverPublic := &tbn254.PointAffine{}
	serverPublic.ScalarMultiplication(&curve.Base, sk) // G*sk

	nodes := 10
	threshold := 3
	shares, err := utils.CreateShares(nodes, threshold, sk)
	if err != nil {
		return nil, err
	}

	idxs := utils.PickRandomIndexes(nodes, threshold)

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

		var resp *utils.OPRFResponse
		resp, err = utils.OPRFEvaluate(shares[idx].PrivateKey, req.MaskedData)
		if err != nil {
			return nil, err
		}

		resps[i] = utils.OutPointToInPoint(resp.Response)
		sharePublicKeys[i] = utils.OutPointToInPoint(shares[idx].PublicKey)
		coefficients[i] = utils.Coeff(peers[i], peers)
		cs[i] = resp.C
		rs[i] = resp.R

	}

	resp, err := utils.OPRFEvaluate(sk, req.MaskedData)
	if err != nil {
		return nil, err
	}

	out, err := utils.OPRFFinalize(serverPublic, req, resp)
	if err != nil {
		return nil, err
	}

	data := &OPRFData{
		SecretData:      [2]frontend.Variable{req.SecretElements[0], req.SecretElements[1]},
		DomainSeparator: new(big.Int).SetBytes([]byte(domainSeparator)),
		Output:          utils.OutPointToInPoint(out),
		Mask:            req.Mask,
	}

	copy(data.Responses[:], resps)
	copy(data.SharePublicKeys[:], sharePublicKeys)
	copy(data.Coefficients[:], coefficients)
	copy(data.C[:], cs)
	copy(data.R[:], rs)

	return data, nil
}
