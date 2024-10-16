package utils

import (
	"math/big"

	twistededwards2 "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
	"github.com/consensys/gnark/std/hash/mimc"
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
	mask := field.NewElement(input.Mask)

	dataPoint, err := hashToPoint(api, curve, input.SecretData)
	if err != nil {
		return err
	}

	masked := curve.ScalarMul(*dataPoint, input.Mask)
	curve.AssertIsOnCurve(masked)

	invMask := helper.packScalarToVar(field.Inverse(mask))
	api.AssertIsEqual(invMask, input.InvMask)
	unMasked := curve.ScalarMul(input.Response, invMask)

	api.AssertIsEqual(input.Nullifier.X, unMasked.X)
	api.AssertIsEqual(input.Nullifier.Y, unMasked.Y)

	/*hField, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}
	hField.Write(input.SecretData)
	hashedSecretData := hField.Sum()
	hField.Reset()

	params := curve.Params()
	basePoint := twistededwards2.Point{
		X: params.Base[0],
		Y: params.Base[1],
	}

	H := curve.ScalarMul(basePoint, hashedSecretData)
	curve.AssertIsOnCurve(H)

	// Compute Input = H * Mask
	mishtiInput := curve.ScalarMul(H, input.Mask)
	field, err := emulated.NewField[BabyParams](api)
	if err != nil {
		return err
	}
	field.Inverse()

	message := []frontend.Variable{mishtiInput.X, mishtiInput.Y, input.MishtiResponse}

	for _, element := range message {
		hField.Write(element)
	}
	hashedMsg := hField.Sum()
	hField.Reset()

	if err := eddsa.Verify(curve, input.Signature, hashedMsg, input.PublicKey, &hField); err != nil {
		return err
	}

	calculatedNullifier := api.Mul(input.MishtiResponse, api.Inverse(input.Mask))
	api.AssertIsEqual(input.Nullifier, calculatedNullifier)*/
	return nil
}

func hashToPoint(api frontend.API, curve twistededwards.Curve, data frontend.Variable) (*twistededwards.Point, error) {
	hField, err := mimc.NewMiMC(api)
	if err != nil {
		return nil, err
	}
	hField.Write(data)
	hashedSecretData := hField.Sum()
	hField.Reset()
	api.Println(hashedSecretData)
	basePoint := twistededwards.Point{
		X: curve.Params().Base[0],
		Y: curve.Params().Base[1],
	}
	dataPoint := curve.ScalarMul(basePoint, hashedSecretData)
	return &dataPoint, nil
}
