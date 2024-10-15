package utils

import (
	"math/big"

	tbn254 "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
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

/*type Scalar = emulated.Element[BabyParams]
type ScalarField = BabyParams
type EmulatedScalarField emulated.Field[BabyParams]

func (b BabyParams) packScalarToVar(s *Scalar) frontend.Variable {
	var fr EmulatedScalarField
	reduced := fr.Reduce(s)
	var res frontend.Variable = 0
	nbBits := fr.BitsPerLimb()
	coef := new(big.Int)
	one := big.NewInt(1)
	for i := range reduced.Limbs {
		res = c.api.Add(res, c.api.Mul(reduced.Limbs[i], coef.Lsh(one, nbBits*uint(i))))
	}
	return res
}*/
