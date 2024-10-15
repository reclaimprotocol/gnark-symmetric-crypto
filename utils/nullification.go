package utils

import (
	"github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/frontend"
	twistededwards2 "github.com/consensys/gnark/std/algebra/native/twistededwards"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/signature/eddsa"
)

type NullificationInput struct {
	PublicKey      eddsa.PublicKey   `gnark:",public"`
	Signature      eddsa.Signature   `gnark:",public"`
	MishtiResponse frontend.Variable `gnark:",public"`
	Nullifier      frontend.Variable `gnark:",public"`
	Mask           frontend.Variable
	SecretData     frontend.Variable
}

func ProcessNullification(api frontend.API, input NullificationInput) error {
	curve, err := twistededwards2.NewEdCurve(api, twistededwards.BN254)
	if err != nil {
		return err
	}
	hField, err := mimc.NewMiMC(api)
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
	api.AssertIsEqual(input.Nullifier, calculatedNullifier)
	return nil
}
