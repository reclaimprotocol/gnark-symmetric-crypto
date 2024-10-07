package utils

import (
	"github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/frontend"
	twistededwards2 "github.com/consensys/gnark/std/algebra/native/twistededwards"
	"github.com/consensys/gnark/std/hash/mimc"
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
	H := HashToCurve(api, curve, input.SecretData)

	// Compute Input = H * Mask
	mishtiInputX := api.Mul(H.X, input.Mask)
	mishtiInputY := api.Mul(H.Y, input.Mask)

	message := []frontend.Variable{mishtiInputX, mishtiInputY, input.MishtiResponse}

	hField, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}
	for _, element := range message {
		hField.Write(element)
	}
	hashedMsg := hField.Sum()
	hField.Reset()

	if err := eddsa.Verify(curve, input.Signature, hashedMsg, input.PublicKey, &hField); err != nil {
		return err
	}

	calculatedNullifier := api.Div(input.MishtiResponse, input.Mask)
	api.AssertIsEqual(input.Nullifier, calculatedNullifier)
	return nil
}

func HashToCurve(api frontend.API, curve twistededwards2.Curve, data frontend.Variable) twistededwards2.Point {
	// Step 1: Hash the data using MiMC hash function
	hFunc, _ := mimc.NewMiMC(api)
	hFunc.Write(data)
	u := hFunc.Sum()

	// Constants
	A := curve.Params().A
	D := curve.Params().D

	// Step 2: Compute Elligator2 mapping
	one := 1
	uSquared := api.Mul(u, u)

	// Compute v = -A / (1 + D * u^2)
	denominator := api.Add(one, api.Mul(D, uSquared))
	v := api.Div(api.Neg(A), denominator)

	// Compute x = v * (1 + u^2) / (1 - u^2)
	numeratorX := api.Mul(v, api.Add(one, uSquared))
	denominatorX := api.Sub(one, uSquared)
	x := api.Div(numeratorX, denominatorX)

	// Compute y numerator and denominator
	numeratorY := api.Sub(u, api.Mul(x, u))
	denominatorY := api.Add(one, api.Mul(x, v))
	y := api.Div(numeratorY, denominatorY)

	return twistededwards2.Point{
		X: x,
		Y: y,
	}
}
