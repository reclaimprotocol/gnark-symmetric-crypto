package utils

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
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

	message := []byte(
		fmt.Sprintf(
			"%s,%s,%s",
			mishtiInputX,
			mishtiInputY,
			input.MishtiResponse,
		),
	)
	paddedData := PadMsg(message, 32, ecc.BN254.ScalarField())

	//var message int
	//_, err = api.Compiler().NewHint(MakeMessageHint, message, mishtiInputX, mishtiInputY, input.MishtiResponse)

	hField, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	return eddsa.Verify(curve, input.Signature, paddedData, input.PublicKey, &hField)
}

//func MakeMessageHint(_ *big.Int, inputs []*big.Int, results []*big.Int) error {
//	message := []byte(fmt.Sprintf("%s,%s,%s", inputs[0], inputs[1], inputs[2]))
//	paddedMsg := PadMsg(message, 32, ecc.BN254.ScalarField())
//	results[0].SetBytes(paddedMsg)
//	return nil
//}

func HashToCurve(api frontend.API, curve twistededwards2.Curve, data frontend.Variable) twistededwards2.Point {
	// Step 1: Hash the data using MiMC hash function
	// Convert data to bytes if necessary

	paddedData := PadMsg([]byte(fmt.Sprintf("%s", data)), 32, ecc.BN254.ScalarField())
	hFunc, _ := mimc.NewMiMC(api)
	hFunc.Write(paddedData)
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
