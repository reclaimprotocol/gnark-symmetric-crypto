package utils

import (
	"github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/frontend"
	twistededwards2 "github.com/consensys/gnark/std/algebra/native/twistededwards"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/signature/eddsa"
)

type NullificationInput struct {
	PublicKey      eddsa.PublicKey     `gnark:",public"`
	Signature      eddsa.Signature     `gnark:",public"`
	MishtiResponse []frontend.Variable `gnark:",public"`
	SecretData     []frontend.Variable
	Mask           frontend.Variable
}

func ProcessNullification(api frontend.API, input NullificationInput) error {

	mimc, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	// Create the curve
	curve, err := twistededwards2.NewEdCurve(api, twistededwards.BN254)
	if err != nil {
		return err
	}

	// Hash the secret data (e.g., SSN) to a curve point
	H := HashToCurve(api, curve, input.SecretData)

	// Compute Input = H * Mask
	mishtiInput := api.Mul(H, input.Mask)

	// Prepare the message
	message := append([]frontend.Variable{mishtiInput}, input.MishtiResponse...)

	return eddsa.Verify(curve, input.Signature, message, input.PublicKey, &mimc)
}

// HashToCurve implements the Elligator2 mapping to map data to a point on the curve
func HashToCurve(api frontend.API, curve twistededwards2.Curve, data []frontend.Variable) twistededwards2.Point {
	// Hash the data using MiMC hash function to get an element in the field
	hFunc, _ := mimc.NewMiMC(api)
	for _, d := range data {
		hFunc.Write(d)
	}
	u := hFunc.Sum()

	// Elligator2 mapping
	// Constants
	A := curve.Params().A
	D := curve.Params().D

	one, _ := api.ConstantValue(1)

	// Compute v = -A / (1 + D * u^2)
	uSquared := api.Mul(u, u)
	denominator := api.Add(one, api.Mul(D, uSquared))
	v := api.DivUnchecked(api.Neg(A), denominator)

	// Compute x = v * (1 + u^2) / (1 - u^2)
	numeratorX := api.Mul(v, api.Add(one, uSquared))
	denominatorX := api.Sub(one, uSquared)
	x := api.DivUnchecked(numeratorX, denominatorX)

	// Compute y numerator and denominator
	numeratorY := api.Sub(u, api.Mul(x, u))
	denominatorY := api.Add(one, api.Mul(x, v))
	y := api.DivUnchecked(numeratorY, denominatorY)

	// Ensure that the point (x, y) lies on the curve
	// Check that -x^2 + y^2 = 1 + d x^2 y^2
	xSquared := api.Mul(x, x)
	ySquared := api.Mul(y, y)
	leftSide := api.Sub(ySquared, xSquared)
	rightSide := api.Add(one, api.Mul(D, xSquared, ySquared))
	api.AssertIsEqual(leftSide, rightSide)

	return twistededwards2.Point{
		X: x,
		Y: y,
	}
}
