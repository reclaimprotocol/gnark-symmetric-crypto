package utils_test

import (
	"github.com/consensys/gnark-crypto/ecc"
	tbn254 "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	"github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/frontend"
	twistededwards2 "github.com/consensys/gnark/std/algebra/native/twistededwards"
	"github.com/consensys/gnark/test"
	"math/big"
	"testing"
)

type mustBeOnCurve struct {
	curveID         twistededwards.ID
	P               twistededwards2.Point
	S1              frontend.Variable
	ScalarMulResult twistededwards2.Point
}

func (circuit *mustBeOnCurve) Define(api frontend.API) error {
	// get edwards curve curve
	curve, err := twistededwards2.NewEdCurve(api, circuit.curveID)
	if err != nil {
		return err
	}
	curve.AssertIsOnCurve(circuit.ScalarMulResult)
	curve.AssertIsOnCurve(circuit.P)
	point := curve.ScalarMul(circuit.P, circuit.S1)
	curve.AssertIsOnCurve(point)
	api.AssertIsEqual(point.Y, circuit.ScalarMulResult.Y)
	api.AssertIsEqual(point.X, circuit.ScalarMulResult.X)
	return nil
}

func TestIsOnCurve(t *testing.T) {

	assert := test.NewAssert(t)
	curve := twistededwards.BN254
	var circuit, validWitness mustBeOnCurve
	circuit.curveID = curve
	snarkCurve := ecc.BN254
	// get curve params
	params, err := twistededwards2.GetCurveParams(curve)
	assert.NoError(err)

	scalar, _ := new(big.Int).SetString("10000000221413143", 10)
	var p1, rs1 tbn254.PointAffine

	p1.X.SetBigInt(params.Base[0])
	p1.Y.SetBigInt(params.Base[1])
	rs1.ScalarMultiplication(&p1, scalar)

	// create witness
	validWitness.P.X = params.Base[0]
	validWitness.P.Y = params.Base[1]
	validWitness.ScalarMulResult = twistededwards2.Point{X: rs1.X, Y: rs1.Y}
	validWitness.S1 = scalar

	// check circuits.
	assert.CheckCircuit(&circuit,
		test.WithValidAssignment(&validWitness),
		test.WithCurves(snarkCurve))

}
