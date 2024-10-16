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
	SecretData *big.Int             // `gnark:",public"`
	Nullifier  twistededwards.Point `gnark:",public"`
	Mask       *big.Int             // `gnark:",public"`
	InvMask    *big.Int             // `gnark:",public"`

	// Proof of DLEQ that Response was created with the same private key as server public key
	ServerPublicKey twistededwards.Point `gnark:",public"`
	VG              twistededwards.Point `gnark:",public"`
	VH              twistededwards.Point `gnark:",public"`
	R               *big.Int             `gnark:",public"`
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

	curve.AssertIsOnCurve(input.Response)
	curve.AssertIsOnCurve(input.Nullifier)
	curve.AssertIsOnCurve(input.ServerPublicKey)
	curve.AssertIsOnCurve(input.VG)
	curve.AssertIsOnCurve(input.VH)

	/*babyModulus := new(BabyParams).Modulus()


	api.AssertIsLessOrEqual(input.Mask, babyModulus)
	api.AssertIsLessOrEqual(input.InvMask, babyModulus)
	api.AssertIsLessOrEqual(input.SecretData, babyModulus)*/

	mask := field.NewElement(input.Mask)

	dataPoint, err := hashToPoint(api, curve, field, helper, input.SecretData)
	if err != nil {
		return err
	}

	masked := curve.ScalarMul(*dataPoint, input.Mask)
	curve.AssertIsOnCurve(masked)

	err = checkDLEQ(api, curve, masked, input.Response, input.ServerPublicKey, input.VG, input.VH, input.R)
	if err != nil {
		return err
	}

	invMask := helper.packScalarToVar(field.Inverse(mask))
	api.AssertIsEqual(invMask, input.InvMask)
	unMasked := curve.ScalarMul(input.Response, invMask)

	api.AssertIsEqual(input.Nullifier.X, unMasked.X)
	api.AssertIsEqual(input.Nullifier.Y, unMasked.Y)

	return nil
}

func checkDLEQ(api frontend.API, curve twistededwards.Curve, masked, response, ServerPublicKey, vg, vh twistededwards.Point, r frontend.Variable) error {
	hField, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}
	hField.Write(vg.X)
	hField.Write(vg.Y)
	hField.Write(vh.X)
	hField.Write(vh.Y)
	hField.Write(curve.Params().Base[0])
	hField.Write(curve.Params().Base[1])
	hField.Write(masked.X)
	hField.Write(masked.Y)

	challenge := hField.Sum()
	hField.Reset()

	basePoint := twistededwards.Point{
		X: curve.Params().Base[0],
		Y: curve.Params().Base[1],
	}

	rG := curve.ScalarMul(basePoint, r)
	chG := curve.ScalarMul(ServerPublicKey, challenge)

	t1 := curve.Add(rG, chG)
	api.AssertIsEqual(t1.X, vg.X)
	api.AssertIsEqual(t1.Y, vg.Y)

	rH := curve.ScalarMul(masked, r)
	cH := curve.ScalarMul(response, challenge)
	t2 := curve.Add(rH, cH)
	api.AssertIsEqual(t2.X, vh.X)
	api.AssertIsEqual(t2.Y, vh.Y)
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
	/*dataBits := bits.ToBinary(api, hashedSecretData, bits.WithNbDigits(254))
	reduced := field.FromBits(dataBits...)
	reduced = field.ReduceStrict(reduced)
	hashedSecretData = helper.packScalarToVar(reduced)*/

	basePoint := twistededwards.Point{
		X: curve.Params().Base[0],
		Y: curve.Params().Base[1],
	}
	dataPoint := curve.ScalarMul(basePoint, hashedSecretData)
	return &dataPoint, nil
}
