package utils_test

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fp"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	tbn254 "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	"github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/frontend"
	twistededwards2 "github.com/consensys/gnark/std/algebra/native/twistededwards"
	"github.com/consensys/gnark/test"
	"math/big"
	"testing"
)

type mustBeOnCurve struct {
	curveID          twistededwards.ID
	P                twistededwards2.Point
	H                twistededwards2.Point
	S1               frontend.Variable
	ScalarMulResult  twistededwards2.Point
	GScalarMulResult twistededwards2.Point
}

func (circuit *mustBeOnCurve) Define(api frontend.API) error {
	// get edwards curve curve
	curve, err := twistededwards2.NewEdCurve(api, circuit.curveID)
	if err != nil {
		return err
	}
	curve.AssertIsOnCurve(circuit.ScalarMulResult)
	curve.AssertIsOnCurve(circuit.P)
	curve.AssertIsOnCurve(circuit.H)

	point := curve.ScalarMul(circuit.P, circuit.S1)
	curve.AssertIsOnCurve(point)
	api.AssertIsEqual(point.Y, circuit.ScalarMulResult.Y)
	api.AssertIsEqual(point.X, circuit.ScalarMulResult.X)

	pointG := curve.ScalarMul(circuit.H, circuit.S1)
	curve.AssertIsOnCurve(pointG)
	api.AssertIsEqual(pointG.Y, circuit.GScalarMulResult.Y)
	api.AssertIsEqual(pointG.X, circuit.GScalarMulResult.X)

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
	var rs1g bn254.G1Affine

	secretDataElement := new(fp.Element).SetBigInt(scalar)
	H := bn254.MapToCurve1(secretDataElement)
	rs1g.ScalarMultiplication(&H, scalar)
	assert.Equal(true, rs1g.IsOnCurve())

	p1.X.SetBigInt(params.Base[0])
	p1.Y.SetBigInt(params.Base[1])
	rs1.ScalarMultiplication(&p1, scalar)
	assert.Equal(true, rs1.IsOnCurve())

	// create witness
	validWitness.P.X = params.Base[0]
	validWitness.P.Y = params.Base[1]
	validWitness.ScalarMulResult = twistededwards2.Point{X: rs1.X, Y: rs1.Y}
	validWitness.S1 = scalar
	validWitness.GScalarMulResult = twistededwards2.Point{X: new(fr.Element).SetBytes(rs1g.X.Marshal()), Y: new(fr.Element).SetBytes(rs1g.Y.Marshal())}
	validWitness.H = twistededwards2.Point{X: new(fr.Element).SetBytes(H.X.Marshal()), Y: new(fr.Element).SetBytes(H.Y.Marshal())}

	// check circuits.
	assert.CheckCircuit(&circuit,
		test.WithValidAssignment(&validWitness),
		test.WithCurves(snarkCurve))

}
