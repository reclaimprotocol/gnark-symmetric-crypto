package utils

import (
	"crypto/rand"
	"math"
	"math/big"
	rnd "math/rand/v2"

	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
)

type Share struct {
	Index      int
	PrivateKey *big.Int
	PublicKey  *twistededwards.PointAffine
}

func TOPRFCreateShares(n, threshold int, secret *big.Int) ([]*Share, error) {
	curve := twistededwards.GetEdwardsCurve()
	gf := &GF{P: TNBCurveOrder}
	a := make([]*big.Int, threshold-1)
	for i := 0; i < threshold-1; i++ {
		r, err := rand.Int(rand.Reader, TNBCurveOrder)
		if err != nil {
			return nil, err
		}
		a[i] = r
	}

	shares := make([]*Share, n)
	// f(x) = a_0 + a_1*x + a_2*x^2 + a_3*x^3 + ⋯ + a_(k−1)*x^(k−1)
	for i := 0; i < n; i++ {
		shareIndex := i + 1
		x := big.NewInt(int64(shareIndex))
		shares[i] = &Share{
			Index: shareIndex,
		}

		shares[i].PrivateKey = new(big.Int).Set(secret)
		for j := 0; j < threshold-1; j++ {
			tmp := gf.Mul(a[j], x)
			for exp := 0; exp < j; exp++ {
				tmp = gf.Mul(tmp, x)
			}
			shares[i].PrivateKey = gf.Add(tmp, shares[i].PrivateKey)
		}

		shares[i].PublicKey = &twistededwards.PointAffine{}
		shares[i].PublicKey.ScalarMultiplication(&curve.Base, shares[i].PrivateKey)
	}

	return shares, nil
}

// Coeff calculates Lagrange coefficient for node with index idx
func Coeff(idx int, peers []int) *big.Int {

	// All peer indexes are [idx] + 1

	gf := &GF{P: TNBCurveOrder}
	peerLen := len(peers)
	iScalar := big.NewInt(int64(idx + 1))
	divident := big.NewInt(1)
	divisor := big.NewInt(1)

	for i := 0; i < peerLen; i++ {
		if peers[i] == idx {
			continue
		}
		tmp := big.NewInt(int64(peers[i] + 1))
		divident = gf.Mul(divident, tmp)
		tmp = gf.Sub(tmp, iScalar)
		divisor = gf.Mul(divisor, tmp)
	}
	divisor = gf.Inv(divisor)
	return gf.Mul(divisor, divident)
}

func TOPRFThresholdMul(idxs []int, responses []*twistededwards.PointAffine) *twistededwards.PointAffine {
	result := &twistededwards.PointAffine{}
	result.X.SetZero()
	result.Y.SetOne()

	for i := 0; i < len(responses); i++ {
		lPoly := Coeff(idxs[i], idxs)
		gki := &twistededwards.PointAffine{}
		gki.ScalarMultiplication(responses[i], lPoly)
		result.Add(result, gki)
	}
	return result
}

type Src struct{}

func (Src) Uint64() uint64 {
	i, _ := rand.Int(rand.Reader, new(big.Int).SetUint64(math.MaxUint64))
	return i.Uint64()
}

func PickRandomIndexes(n, k int) []int {
	r := rnd.New(Src{})
	idxs := r.Perm(n)
	return idxs[:k]
}
