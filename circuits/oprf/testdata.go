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

func PrepareTestData(secretData string) (*OPRFData, error) {
	curve := tbn254.GetEdwardsCurve()
	secretBytes := []byte(secretData)
	if len(secretBytes) > 31*2 {
		return nil, errors.New("secret data too big")
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
	if !H.IsOnCurve() {
		return nil, fmt.Errorf("point is not on curve")
	}

	// mask
	masked := &tbn254.PointAffine{}
	masked.ScalarMultiplication(H, mask) // H*Proof

	// server part
	resp := &tbn254.PointAffine{}
	resp.ScalarMultiplication(masked, sk) // H*Proof*sk

	// output calc
	invR := new(big.Int)
	invR.ModInverse(mask, BN254ScalarField) // mask^-1

	output := &tbn254.PointAffine{}
	output.ScalarMultiplication(resp, invR) // H *mask * sk * mask^-1 = H * sk

	c, r, err := ProveDLEQ(sk, serverPublic, resp, masked)
	if err != nil {
		return nil, err
	}

	return &OPRFData{
		Response:        OutPointToInPoint(resp),
		SecretData:      [2]frontend.Variable{secretElements[0], secretElements[1]},
		Output:          OutPointToInPoint(output),
		Mask:            mask,
		ServerPublicKey: OutPointToInPoint(serverPublic),
		C:               c,
		S:               r,
	}, nil
}
