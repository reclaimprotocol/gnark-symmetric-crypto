package toprf

import (
	tbn "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/math/bits"
	"github.com/consensys/gnark/std/math/emulated"
)

const Threshold = 2

type TOPRFParams struct {
	SecretData      [2]frontend.Variable
	DomainSeparator frontend.Variable `gnark:",public"`
	Mask            frontend.Variable

	Responses    [Threshold]twistededwards.Point `gnark:",public"` // responses per each node
	Coefficients [Threshold]frontend.Variable    `gnark:",public"` // coeffs for reconstructing point & public key

	// Proofs of DLEQ per node
	SharePublicKeys [Threshold]twistededwards.Point `gnark:",public"`
	C               [Threshold]frontend.Variable    `gnark:",public"`
	R               [Threshold]frontend.Variable    `gnark:",public"`

	Output frontend.Variable `gnark:",public"` // hash of deblinded point + secret data
}

type TOPRF struct {
	*TOPRFParams
}

func (n *TOPRF) Define(api frontend.API) error {
	return VerifyTOPRF(api, n.TOPRFParams)
}

func VerifyTOPRF(api frontend.API, p *TOPRFParams) error {
	curve, err := twistededwards.NewEdCurve(api, tbn.BN254)
	if err != nil {
		return err
	}
	field, err := emulated.NewField[BabyJubParams](api)
	if err != nil {
		return err
	}
	helper := NewBabyJubFieldHelper(api)

	maskBits := bits.ToBinary(api, p.Mask, bits.WithNbDigits(api.Compiler().Field().BitLen()))
	mask := field.FromBits(maskBits...)

	dataPoint, err := hashToPoint(api, curve, p.SecretData, p.DomainSeparator)
	if err != nil {
		return err
	}

	masked := curve.ScalarMul(*dataPoint, p.Mask)

	// verify each DLEQ first

	for i := 0; i < Threshold; i++ {
		curve.AssertIsOnCurve(p.Responses[i])
		curve.AssertIsOnCurve(p.SharePublicKeys[i])
		err = checkDLEQ(api, curve, masked, p.Responses[i], p.SharePublicKeys[i], p.C[i], p.R[i])
		if err != nil {
			return err
		}
	}

	response := TOPRFMult(curve, p.Responses[:], p.Coefficients[:])

	invMask := helper.packScalarToVar(field.Inverse(mask))
	unMasked := curve.ScalarMul(response, invMask)

	hash, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	hash.Write(unMasked.X)
	hash.Write(unMasked.Y)
	hash.Write(p.SecretData[0])
	hash.Write(p.SecretData[1])
	out := hash.Sum()

	api.AssertIsEqual(p.Output, out)
	return nil
}

func TOPRFMult(curve twistededwards.Curve, points []twistededwards.Point, coeffs []frontend.Variable) twistededwards.Point {
	result := twistededwards.Point{
		X: 0,
		Y: 1,
	}

	for i := 0; i < len(points); i++ {
		lPoly := coeffs[i]
		gki := curve.ScalarMul(points[i], lPoly)
		result = curve.Add(result, gki)
	}
	return result

}

func checkDLEQ(api frontend.API, curve twistededwards.Curve, masked, response, serverPublicKey twistededwards.Point, challenge, r frontend.Variable) error {
	hField, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	basePoint := twistededwards.Point{
		X: curve.Params().Base[0],
		Y: curve.Params().Base[1],
	}

	rG := curve.ScalarMul(basePoint, r)
	chG := curve.ScalarMul(serverPublicKey, challenge)
	t1 := curve.Add(rG, chG)

	rH := curve.ScalarMul(masked, r)
	cH := curve.ScalarMul(response, challenge)
	t2 := curve.Add(rH, cH)

	hField.Write(basePoint.X)
	hField.Write(basePoint.Y)

	hField.Write(serverPublicKey.X)
	hField.Write(serverPublicKey.Y)

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

	basePoint := twistededwards.Point{
		X: curve.Params().Base[0],
		Y: curve.Params().Base[1],
	}
	dataPoint := curve.ScalarMul(basePoint, hashedSecretData)
	return &dataPoint, nil
}
