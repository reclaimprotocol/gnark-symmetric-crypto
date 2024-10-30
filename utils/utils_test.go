package utils

import (
	"encoding/base64"
	"math/big"
	"testing"

	tbn254 "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	"github.com/stretchr/testify/require"
)

func TestOPRF(t *testing.T) {
	serverPrivate := "A3q7HrA+10FUiL0Q9lrDBRdRuoq752oREn9STszgLEo="
	serverPublicStr := "dGEZEZY4qexS2WyOL8KDcv99BWjL7ivaKvvarCcbYCU="
	skBytes, _ := base64.StdEncoding.DecodeString(serverPrivate)
	pubBytes, _ := base64.StdEncoding.DecodeString(serverPublicStr)

	// server secret & public
	sk := new(big.Int).SetBytes(skBytes)
	serverPublic := &tbn254.PointAffine{}
	err := serverPublic.Unmarshal(pubBytes)
	require.NoError(t, err)

	email := "test@example.com"
	ds := "reclaim"

	req, err := GenerateOPRFRequest(email, ds)
	require.NoError(t, err)

	resp, err := OPRF(sk, req.MaskedData)
	require.NoError(t, err)

	res, err := ProcessOPRFResponse(serverPublic, req, resp)
	require.NoError(t, err)

	require.Equal(t, "jH6BFWtyH0HQGJCJ+vM9eIkBdXrLypeAOSmwz2UtxYs=", base64.StdEncoding.EncodeToString(res.Marshal()))

	nodes := 100
	threshold := 50
	shares, err := CreateShares(nodes, threshold, sk)
	require.NoError(t, err)
	resps := make([]*tbn254.PointAffine, threshold)
	for i := 0; i < threshold; i++ {
		resp, err = OPRF(shares[i].PrivateKey, req.MaskedData)
		require.NoError(t, err)
		resps[i] = resp.Response
	}

	idxs := make([]int, threshold)
	for i := 0; i < threshold; i++ {
		idxs[i] = i
	}

	evaled := TOPRFThresholdMult(idxs, resps)

	// output calc
	invR := new(big.Int)
	invR.ModInverse(req.Mask, TNBCurveOrder) // mask^-1

	output := &tbn254.PointAffine{}
	output.ScalarMultiplication(evaled, invR) // H *mask * sk * mask^-1 = H * sk
	require.Equal(t, "jH6BFWtyH0HQGJCJ+vM9eIkBdXrLypeAOSmwz2UtxYs=", base64.StdEncoding.EncodeToString(output.Marshal()))
}
