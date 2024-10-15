package utils

import (
	"math/big"

	tbn254 "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
)

type BabyParams struct {
}

func (b BabyParams) NbLimbs() uint     { return 4 }
func (b BabyParams) BitsPerLimb() uint { return 64 }
func (b BabyParams) IsPrime() bool     { return true }
func (b BabyParams) Modulus() *big.Int {
	order := tbn254.GetEdwardsCurve().Order
	return &order
}

type ScalarField = BabyParams
type Scalar = emulated.Element[BabyParams]

type BabyField struct {
	api frontend.API
	fr  *emulated.Field[ScalarField]
}

func NewBabyFieldHelper(api frontend.API) *BabyField {
	field, err := emulated.NewField[ScalarField](api)
	if err != nil {
		panic(err)
	}
	return &BabyField{
		api: api,
		fr:  field,
	}
}

func (b BabyField) packScalarToVar(s *Scalar) frontend.Variable {
	var fr ScalarField
	reduced := b.fr.Reduce(s)
	var res frontend.Variable = 0
	nbBits := fr.BitsPerLimb()
	coef := new(big.Int)
	one := big.NewInt(1)
	for i := range reduced.Limbs {
		res = b.api.Add(res, b.api.Mul(reduced.Limbs[i], coef.Lsh(one, nbBits*uint(i))))
	}
	return res
}
