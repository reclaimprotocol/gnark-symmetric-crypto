package utils

import (
	"math/big"

	twistededwards2 "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/math/bits"
	"github.com/consensys/gnark/std/math/emulated"
)

type NullificationInput struct {
	Response   twistededwards.Point `gnark:",public"`
	SecretData *big.Int             `gnark:",public"`
	Nullifier  twistededwards.Point `gnark:",public"`
	Mask       *big.Int             `gnark:",public"`
	InvMask    *big.Int             `gnark:",public"`
}

func ProcessNullification(api frontend.API, input NullificationInput) error {
	curve, err := twistededwards.NewEdCurve(api, twistededwards2.BN254)
	if err != nil {
		return err
	}
	field, err := emulated.NewField[BabyParams](api)
	if err != nil {
		return err
	}
	helper := NewBabyFieldHelper(api)
	babyModulus := new(BabyParams).Modulus()

	curve.AssertIsOnCurve(input.Response)
	curve.AssertIsOnCurve(input.Nullifier)
	api.AssertIsLessOrEqual(input.Mask, babyModulus)
	api.AssertIsLessOrEqual(input.InvMask, babyModulus)
	api.AssertIsLessOrEqual(input.SecretData, babyModulus)

	mask := field.NewElement(input.Mask)

	dataPoint, err := hashToPoint(api, curve, field, helper, input.SecretData)
	if err != nil {
		return err
	}

	masked := curve.ScalarMul(*dataPoint, input.Mask)
	curve.AssertIsOnCurve(masked)

	// here we check DLEQ

	invMask := helper.packScalarToVar(field.Inverse(mask))
	api.AssertIsEqual(invMask, input.InvMask)
	unMasked := curve.ScalarMul(input.Response, invMask)

	api.AssertIsEqual(input.Nullifier.X, unMasked.X)
	api.AssertIsEqual(input.Nullifier.Y, unMasked.Y)

	return nil
}

func hashToPoint(api frontend.API, curve twistededwards.Curve, field *emulated.Field[BabyParams], helper *BabyField, data frontend.Variable) (*twistededwards.Point, error) {
	hField, err := mimc.NewMiMC(api)
	if err != nil {
		return nil, err
	}
	hField.Write(data)
	hashedSecretData := hField.Sum()
	hField.Reset()

	// reduce modulo babyJub order, might omit in future to save constraints
	dataBits := bits.ToBinary(api, hashedSecretData, bits.WithNbDigits(254))
	reduced := field.FromBits(dataBits...)
	reduced = field.ReduceStrict(reduced)
	hashedSecretData = helper.packScalarToVar(reduced)

	basePoint := twistededwards.Point{
		X: curve.Params().Base[0],
		Y: curve.Params().Base[1],
	}
	dataPoint := curve.ScalarMul(basePoint, hashedSecretData)
	return &dataPoint, nil
}
