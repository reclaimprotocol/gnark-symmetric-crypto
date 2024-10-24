package oprf

import (
	tbn "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/math/bits"
	"github.com/consensys/gnark/std/math/emulated"
)

type OPRFData struct {
	SecretData      [2]frontend.Variable
	DomainSeparator frontend.Variable
	Mask            frontend.Variable
	Response        twistededwards.Point `gnark:",public"`
	Output          twistededwards.Point `gnark:",public"`
	// Proof of DLEQ that Response was created with the same private key as server public key
	ServerPublicKey twistededwards.Point `gnark:",public"`
	C               frontend.Variable    `gnark:",public"`
	S               frontend.Variable    `gnark:",public"`
}

type OPRF struct {
	*OPRFData
}

func (n *OPRF) Define(api frontend.API) error {
	return VerifyOPRF(api, n.OPRFData)
}

func VerifyOPRF(api frontend.API, n *OPRFData) error {
	curve, err := twistededwards.NewEdCurve(api, tbn.BN254)
	if err != nil {
		return err
	}
	field, err := emulated.NewField[BabyJubParams](api)
	if err != nil {
		return err
	}
	helper := NewBabyJubFieldHelper(api)

	curve.AssertIsOnCurve(n.Response)
	curve.AssertIsOnCurve(n.Output)
	curve.AssertIsOnCurve(n.ServerPublicKey)

	/*babyModulus := new(BabyJubParams).Modulus()
	api.AssertIsLessOrEqual(n.Mask, babyModulus)
	api.AssertIsLessOrEqual(n.InvMask, babyModulus)
	api.AssertIsLessOrEqual(n.SecretData, babyModulus)*/

	maskBits := bits.ToBinary(api, n.Mask, bits.WithNbDigits(api.Compiler().Field().BitLen()))
	mask := field.FromBits(maskBits...)

	dataPoint, err := hashToPoint(api, curve, n.SecretData, n.DomainSeparator)
	if err != nil {
		return err
	}

	masked := curve.ScalarMul(*dataPoint, n.Mask)

	err = checkDLEQ(api, curve, masked, n.Response, n.ServerPublicKey, n.C, n.S)
	if err != nil {
		return err
	}

	invMask := helper.packScalarToVar(field.Inverse(mask))
	unMasked := curve.ScalarMul(n.Response, invMask)

	api.AssertIsEqual(n.Output.X, unMasked.X)
	api.AssertIsEqual(n.Output.Y, unMasked.Y)

	return nil
}

func checkDLEQ(api frontend.API, curve twistededwards.Curve, masked, response, ServerPublicKey twistededwards.Point, challenge, r frontend.Variable) error {
	hField, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	basePoint := twistededwards.Point{
		X: curve.Params().Base[0],
		Y: curve.Params().Base[1],
	}

	rG := curve.ScalarMul(basePoint, r)
	chG := curve.ScalarMul(ServerPublicKey, challenge)
	t1 := curve.Add(rG, chG)

	rH := curve.ScalarMul(masked, r)
	cH := curve.ScalarMul(response, challenge)
	t2 := curve.Add(rH, cH)

	hField.Write(basePoint.X)
	hField.Write(basePoint.Y)

	hField.Write(ServerPublicKey.X)
	hField.Write(ServerPublicKey.Y)

	hField.Write(t1.X)
	hField.Write(t1.Y)

	hField.Write(t2.X)
	hField.Write(t2.Y)

	hField.Write(masked.X)
	hField.Write(masked.Y)

	hField.Write(response.X)
	hField.Write(response.Y)

	expectedChallenge := hField.Sum()
	hField.Reset()
	api.AssertIsEqual(expectedChallenge, challenge)
	return nil
}

func hashToPoint(api frontend.API, curve twistededwards.Curve, data [2]frontend.Variable, domainSeparator frontend.Variable) (*twistededwards.Point, error) {
	hField, err := mimc.NewMiMC(api)
	if err != nil {
		return nil, err
	}
	hField.Write(data[0])
	hField.Write(data[1])
	hField.Write(domainSeparator)
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
