package libraries

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	prover "gnark-symmetric-crypto/libraries/prover/impl"
	verifier "gnark-symmetric-crypto/libraries/verifier/impl"
	"gnark-symmetric-crypto/utils"
	"math"
	"math/big"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

var chachaKey, aes128Key, aes256Key, chachaR1CS, aes128r1cs, aes256r1cs []byte

func init() {
	chachaKey, _ = fetchFile("pk.chacha20")
	aes128Key, _ = fetchFile("pk.aes128")
	aes256Key, _ = fetchFile("pk.aes256")

	chachaR1CS, _ = fetchFile("r1cs.chacha20")
	aes128r1cs, _ = fetchFile("r1cs.aes128")
	aes256r1cs, _ = fetchFile("r1cs.aes256")
}

func TestInit(t *testing.T) {
	assert := test.NewAssert(t)
	assert.True(prover.InitAlgorithm(prover.CHACHA20, chachaKey, chachaR1CS))
	assert.True(prover.InitAlgorithm(prover.AES_128, aes128Key, aes128r1cs))
	assert.True(prover.InitAlgorithm(prover.AES_256, aes256Key, aes256r1cs))

}

func TestTiming(t *testing.T) {
	t.Skip()
	assert := test.NewAssert(t)
	assert.True(prover.InitAlgorithm(prover.CHACHA20, chachaKey, chachaR1CS))
	for i := 0; i < 100; i++ {
		params := `{"cipher":"chacha20","key":[[0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1],[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]],"nonce":[[0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1],[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]],"counter":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1],"input":[[1,0,0,1,1,0,0,1,0,1,0,0,1,0,0,0,1,1,0,0,0,0,1,0,0,0,1,0,0,0,0,1],[1,1,1,0,1,0,1,1,1,0,0,1,0,0,1,0,1,1,1,1,0,1,0,0,0,1,0,1,1,0,1,1],[1,1,1,0,0,0,1,1,0,0,0,0,0,0,1,1,0,1,0,1,0,0,1,1,1,1,0,1,0,1,0,1],[0,1,1,1,1,0,1,1,0,0,1,0,1,1,0,0,0,0,0,0,1,0,1,1,0,1,0,1,0,1,0,1],[0,0,0,0,1,1,1,1,1,1,1,1,1,0,0,0,0,0,1,1,1,0,0,1,1,1,1,0,0,0,1,1],[0,0,1,0,1,0,1,0,1,1,1,0,1,0,1,1,0,1,1,1,0,0,1,1,0,1,1,0,1,0,0,0],[0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0],[0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0],[0,0,1,0,1,0,0,1,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0],[1,1,0,1,1,0,1,0,0,1,1,0,0,0,1,0,1,0,0,0,0,1,1,0,0,1,0,0,0,0,0,0],[1,0,0,1,0,1,0,0,0,1,0,1,0,0,1,0,0,1,0,0,0,1,1,1,0,1,0,1,1,1,1,1],[0,1,0,0,0,1,1,1,0,1,1,0,1,1,1,0,0,0,1,0,1,0,1,1,1,1,0,0,0,0,1,1],[1,0,0,0,1,1,1,0,1,0,1,0,0,0,1,1,1,0,0,0,0,1,0,0,1,1,0,1,1,1,0,1],[0,1,1,1,1,0,0,1,1,1,0,0,0,1,1,0,1,1,1,0,0,1,0,0,1,0,0,1,1,1,1,1],[0,0,1,0,1,1,1,0,0,1,0,1,0,0,0,1,1,1,0,0,0,0,1,1,0,1,1,1,0,0,1,1],[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]]}`
		tt := time.Now()
		res := prover.Prove([]byte(params))
		assert.NotNil(res)
		fmt.Println(time.Now().Sub(tt))
	}
}

type InputParamsAES struct {
	Input []int `json:"input"`
}

type InputParamsChaCha struct {
	Input [][]byte `json:"input"`
}

type InputVerifyParams struct {
	Cipher        string `json:"cipher"`
	Proof         string `json:"proof"`
	PublicSignals []int  `json:"publicSignals"`
}

func TestProveVerify(t *testing.T) {
	assert := test.NewAssert(t)

	proofs := make([][]byte, 0, 3)

	wg := new(sync.WaitGroup)
	wg.Add(3)
	go func() {
		assert.True(prover.InitAlgorithm(prover.CHACHA20, chachaKey, nil))
		params := `{"cipher":"chacha20","key":[[0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1],[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]],"nonce":[[0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1],[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]],"counter":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1],"input":[[1,0,0,1,1,0,0,1,0,1,0,0,1,0,0,0,1,1,0,0,0,0,1,0,0,0,1,0,0,0,0,1],[1,1,1,0,1,0,1,1,1,0,0,1,0,0,1,0,1,1,1,1,0,1,0,0,0,1,0,1,1,0,1,1],[1,1,1,0,0,0,1,1,0,0,0,0,0,0,1,1,0,1,0,1,0,0,1,1,1,1,0,1,0,1,0,1],[0,1,1,1,1,0,1,1,0,0,1,0,1,1,0,0,0,0,0,0,1,0,1,1,0,1,0,1,0,1,0,1],[0,0,0,0,1,1,1,1,1,1,1,1,1,0,0,0,0,0,1,1,1,0,0,1,1,1,1,0,0,0,1,1],[0,0,1,0,1,0,1,0,1,1,1,0,1,0,1,1,0,1,1,1,0,0,1,1,0,1,1,0,1,0,0,0],[0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0],[0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0],[0,0,1,0,1,0,0,1,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0],[1,1,0,1,1,0,1,0,0,1,1,0,0,0,1,0,1,0,0,0,0,1,1,0,0,1,0,0,0,0,0,0],[1,0,0,1,0,1,0,0,0,1,0,1,0,0,1,0,0,1,0,0,0,1,1,1,0,1,0,1,1,1,1,1],[0,1,0,0,0,1,1,1,0,1,1,0,1,1,1,0,0,0,1,0,1,0,1,1,1,1,0,0,0,0,1,1],[1,0,0,0,1,1,1,0,1,0,1,0,0,0,1,1,1,0,0,0,0,1,0,0,1,1,0,1,1,1,0,1],[0,1,1,1,1,0,0,1,1,1,0,0,0,1,1,0,1,1,1,0,0,1,0,0,1,0,0,1,1,1,1,1],[0,0,1,0,1,1,1,0,0,1,0,1,0,0,0,1,1,1,0,0,0,0,1,1,0,1,1,1,0,0,1,1],[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]]}`
		res := prover.Prove([]byte(params))
		assert.NotNil(res)

		var outParams *prover.OutputParams
		json.Unmarshal(res, &outParams)

		var inParams *InputParamsChaCha
		json.Unmarshal([]byte(params), &inParams)

		bts := bytes.Join(inParams.Input, nil)
		ints := make([]int, len(bts))
		for i := 0; i < len(ints); i++ {
			ints[i] = int(bts[i])
		}

		inParams2 := &InputVerifyParams{
			Cipher:        "chacha20",
			Proof:         outParams.Proof.ProofJson,
			PublicSignals: append(outParams.PublicSignals, ints...),
		}
		inBuf, _ := json.Marshal(inParams2)
		proofs = append(proofs, inBuf)
		wg.Done()
	}()

	go func() {
		assert.True(prover.InitAlgorithm(prover.AES_128, aes128Key, nil))
		params := `{"cipher":"aes-128-ctr","key":[0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"nonce":[0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"counter":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0],"input":[0,0,1,1,1,0,1,1,0,0,1,0,1,1,1,1,0,1,0,0,0,0,0,1,0,1,0,0,1,0,0,0,0,1,1,1,0,0,0,0,1,1,0,0,1,1,0,0,1,1,0,0,1,1,0,0,0,0,0,1,0,1,1,1,1,0,0,0,0,0,1,1,1,1,1,0,1,1,1,1,1,0,1,0,0,1,0,0,0,1,0,0,1,1,0,1,0,0,1,1,0,1,1,0,0,0,0,0,1,1,0,1,1,0,1,1,0,1,1,0,1,0,0,1,0,0,0,0,0,1,0,1,1,1,0,0,1,0,1,1,1,1,1,0,1,1,1,0,0,0,0,0,1,0,1,1,0,0,1,0,1,0,0,1,0,0,0,1,0,1,0,0,1,1,0,1,1,0,0,1,0,0,1,1,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,1,0,0,1,0,0,1,1,1,1,0,0,0,1,1,1,0,1,1,1,1,0,1,1,1,1,0,1,0,0,1,1,0,0,0,1,0,1,0,0,1,0,0,0,1,0,0,0,0,1,0,0,1,0,0,1,0,0,0,1,0,1,1,0,0,0,0,0,0,0,0,1,0,1,0,0,1,1,0,1,0,0,1,1,0,1,0,0,0,1,0,1,1,1,1,0,0,0,1,0,1,0,0,1,0,1,1,0,1,0,0,1,1,1,0,1,0,0,1,1,0,0,0,0,0,1,0,1,0,0,0,1,1,1,1,1,1,1,1,1,1,1,0,0,1,0,1,0,0,0,0,0,0,1,0,1,0,0,1,1,0,1,1,0,0,1,1,1,1,0,0,1,0,0,1,0,1,1,1,1,0,1,1,1,0,1,0,1,1,0,1,1,1,0,0,0,0,1,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]}`
		res := prover.Prove([]byte(params))
		assert.NotNil(res)

		var outParams *prover.OutputParams
		json.Unmarshal(res, &outParams)

		var inParams *InputParamsAES
		json.Unmarshal([]byte(params), &inParams)

		inParams2 := &InputVerifyParams{
			Cipher:        "aes-128-ctr",
			Proof:         outParams.Proof.ProofJson,
			PublicSignals: append(outParams.PublicSignals, inParams.Input...),
		}
		inBuf, _ := json.Marshal(inParams2)
		proofs = append(proofs, inBuf)
		wg.Done()
	}()

	go func() {
		assert.True(prover.InitAlgorithm(prover.AES_256, aes256Key, nil))
		params := `{"cipher":"aes-256-ctr","key":[0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"nonce":[0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"counter":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0],"input":[0,0,1,0,1,1,0,1,1,0,0,0,1,0,0,1,0,1,0,1,1,1,1,1,1,0,0,0,0,0,1,1,1,1,0,0,1,1,0,1,0,0,1,0,0,1,1,0,1,1,1,1,0,1,0,1,0,0,1,0,0,0,1,0,1,0,0,0,1,0,1,1,0,1,1,1,1,1,0,0,0,1,0,0,1,0,1,0,1,1,0,0,1,1,0,0,0,0,1,1,0,0,0,1,0,1,1,1,0,0,1,0,1,0,1,1,0,1,0,0,0,1,1,0,0,0,1,1,1,0,0,1,0,1,0,0,0,1,1,1,0,1,0,0,0,0,1,1,0,1,0,1,0,0,0,1,0,1,1,0,0,1,1,0,0,0,1,0,1,1,1,1,1,1,0,0,1,0,1,1,0,1,0,1,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,1,0,0,0,0,1,1,1,1,0,0,1,0,0,0,0,1,1,1,1,0,1,0,0,1,0,0,0,0,0,1,1,1,0,0,1,1,1,0,0,0,0,0,0,0,1,1,1,0,0,1,0,1,0,0,0,1,0,0,0,0,0,1,0,1,0,1,1,0,1,0,0,1,0,1,0,0,1,0,1,1,0,1,0,1,0,1,0,0,1,0,1,0,0,0,0,0,0,1,0,1,1,1,0,0,1,1,1,1,0,1,0,1,1,0,0,0,0,0,1,1,1,1,1,0,0,0,0,0,0,1,1,0,0,1,0,1,1,1,0,0,1,0,1,1,1,1,0,0,0,1,0,1,0,1,0,0,1,1,1,0,0,1,0,0,1,0,1,1,0,1,1,0,0,1,1,1,0,0,0,1,0,1,1,0,1,1,1,1,1,0,1,1,0,1,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]}`
		res := prover.Prove([]byte(params))
		assert.NotNil(res)

		var outParams *prover.OutputParams
		json.Unmarshal(res, &outParams)

		var inParams *InputParamsAES
		json.Unmarshal([]byte(params), &inParams)

		inParams2 := &InputVerifyParams{
			Cipher:        "aes-256-ctr",
			Proof:         outParams.Proof.ProofJson,
			PublicSignals: append(outParams.PublicSignals, inParams.Input...),
		}
		inBuf, _ := json.Marshal(inParams2)
		proofs = append(proofs, inBuf)
		wg.Done()
	}()

	wg.Wait()

	assert.Equal(3, len(proofs))

	for _, proof := range proofs {
		assert.True(verifier.Verify(proof))
	}
}

func TestPanic(t *testing.T) {
	assert := test.NewAssert(t)
	params := `{"cipher":"aes-256-ctr1","key":[0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"nonce":[0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"counter":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0],"input":[0,0,1,0,1,1,0,1,1,0,0,0,1,0,0,1,0,1,0,1,1,1,1,1,1,0,0,0,0,0,1,1,1,1,0,0,1,1,0,1,0,0,1,0,0,1,1,0,1,1,1,1,0,1,0,1,0,0,1,0,0,0,1,0,1,0,0,0,1,0,1,1,0,1,1,1,1,1,0,0,0,1,0,0,1,0,1,0,1,1,0,0,1,1,0,0,0,0,1,1,0,0,0,1,0,1,1,1,0,0,1,0,1,0,1,1,0,1,0,0,0,1,1,0,0,0,1,1,1,0,0,1,0,1,0,0,0,1,1,1,0,1,0,0,0,0,1,1,0,1,0,1,0,0,0,1,0,1,1,0,0,1,1,0,0,0,1,0,1,1,1,1,1,1,0,0,1,0,1,1,0,1,0,1,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,1,0,0,0,0,1,1,1,1,0,0,1,0,0,0,0,1,1,1,1,0,1,0,0,1,0,0,0,0,0,1,1,1,0,0,1,1,1,0,0,0,0,0,0,0,1,1,1,0,0,1,0,1,0,0,0,1,0,0,0,0,0,1,0,1,0,1,1,0,1,0,0,1,0,1,0,0,1,0,1,1,0,1,0,1,0,1,0,0,1,0,1,0,0,0,0,0,0,1,0,1,1,1,0,0,1,1,1,1,0,1,0,1,1,0,0,0,0,0,1,1,1,1,1,0,0,0,0,0,0,1,1,0,0,1,0,1,1,1,0,0,1,0,1,1,1,1,0,0,0,1,0,1,0,1,0,0,1,1,1,0,0,1,0,0,1,0,1,1,0,1,1,0,0,1,1,1,0,0,0,1,0,1,1,0,1,1,1,1,1,0,1,1,0,1,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]}`
	assert.Panics(func() {
		prover.Prove([]byte(params))
	})

	assert.False(verifier.Verify([]byte(`{"cipher":"chacha20"}`)))
}

func TestFullChaCha20(t *testing.T) {
	assert := test.NewAssert(t)
	assert.True(prover.InitAlgorithm(prover.CHACHA20, chachaKey, chachaR1CS))
	bKey := make([]byte, 32)
	bNonce := make([]byte, 12)

	bPt := make([]byte, 64)

	tmp, _ := rand.Int(rand.Reader, big.NewInt(math.MaxUint32))
	counter := uint32(tmp.Uint64())

	rand.Read(bKey)
	rand.Read(bNonce)
	rand.Read(bPt)

	key := utils.UintsToBits(utils.BytesToUint32LERaw(bKey))
	nonce := utils.UintsToBits(utils.BytesToUint32LERaw(bNonce))
	cnt := utils.Uint32ToBitsLE(counter)

	plaintext := utils.UintsToBits(utils.BytesToUint32BERaw(bPt))

	pt := make([]uint8, len(plaintext)*32)
	for i := 0; i < len(plaintext); i++ {
		for j := 0; j < 32; j++ {
			pt[i*32+j] = uint8(plaintext[i][j].(uint))
		}
	}

	inputParams := struct {
		Cipher  string                  `json:"cipher"`
		Key     [][32]frontend.Variable `json:"key"`
		Nonce   [][32]frontend.Variable `json:"nonce"`
		Counter [32]frontend.Variable   `json:"counter"`
		Input   [][32]frontend.Variable `json:"input"`
	}{
		Cipher:  "chacha20",
		Key:     key,
		Nonce:   nonce,
		Counter: cnt,
		Input:   plaintext,
	}

	buf, _ := json.Marshal(inputParams)

	res := prover.Prove(buf)
	assert.True(len(res) > 0)
	var outParams *prover.OutputParams
	json.Unmarshal(res, &outParams)

	inParams := &verifier.InputVerifyParams{
		Cipher:        "chacha20",
		Proof:         outParams.Proof.ProofJson,
		PublicSignals: append(toUint8(outParams.PublicSignals), pt...),
	}
	inBuf, _ := json.Marshal(inParams)
	assert.True(verifier.Verify(inBuf))
}

func Benchmark_ProveAES128(b *testing.B) {
	prover.InitAlgorithm(prover.AES_128, aes128Key, aes128r1cs)
	b.ResetTimer()
	params := `{"cipher":"aes-128-ctr","key":[0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"nonce":[0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"counter":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0],"input":[0,0,1,1,1,0,1,1,0,0,1,0,1,1,1,1,0,1,0,0,0,0,0,1,0,1,0,0,1,0,0,0,0,1,1,1,0,0,0,0,1,1,0,0,1,1,0,0,1,1,0,0,1,1,0,0,0,0,0,1,0,1,1,1,1,0,0,0,0,0,1,1,1,1,1,0,1,1,1,1,1,0,1,0,0,1,0,0,0,1,0,0,1,1,0,1,0,0,1,1,0,1,1,0,0,0,0,0,1,1,0,1,1,0,1,1,0,1,1,0,1,0,0,1,0,0,0,0,0,1,0,1,1,1,0,0,1,0,1,1,1,1,1,0,1,1,1,0,0,0,0,0,1,0,1,1,0,0,1,0,1,0,0,1,0,0,0,1,0,1,0,0,1,1,0,1,1,0,0,1,0,0,1,1,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,1,0,0,1,0,0,1,1,1,1,0,0,0,1,1,1,0,1,1,1,1,0,1,1,1,1,0,1,0,0,1,1,0,0,0,1,0,1,0,0,1,0,0,0,1,0,0,0,0,1,0,0,1,0,0,1,0,0,0,1,0,1,1,0,0,0,0,0,0,0,0,1,0,1,0,0,1,1,0,1,0,0,1,1,0,1,0,0,0,1,0,1,1,1,1,0,0,0,1,0,1,0,0,1,0,1,1,0,1,0,0,1,1,1,0,1,0,0,1,1,0,0,0,0,0,1,0,1,0,0,0,1,1,1,1,1,1,1,1,1,1,1,0,0,1,0,1,0,0,0,0,0,0,1,0,1,0,0,1,1,0,1,1,0,0,1,1,1,1,0,0,1,0,0,1,0,1,1,1,1,0,1,1,1,0,1,0,1,1,0,1,1,1,0,0,0,0,1,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]}`
	for i := 0; i < b.N; i++ {
		prover.Prove([]byte(params))
	}
	b.ReportAllocs()
}

func Benchmark_ProveAES256(b *testing.B) {
	prover.InitAlgorithm(prover.AES_256, aes256Key, aes256r1cs)
	b.ResetTimer()
	params := `{"cipher":"aes-256-ctr","key":[0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"nonce":[0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"counter":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0],"input":[0,0,1,0,1,1,0,1,1,0,0,0,1,0,0,1,0,1,0,1,1,1,1,1,1,0,0,0,0,0,1,1,1,1,0,0,1,1,0,1,0,0,1,0,0,1,1,0,1,1,1,1,0,1,0,1,0,0,1,0,0,0,1,0,1,0,0,0,1,0,1,1,0,1,1,1,1,1,0,0,0,1,0,0,1,0,1,0,1,1,0,0,1,1,0,0,0,0,1,1,0,0,0,1,0,1,1,1,0,0,1,0,1,0,1,1,0,1,0,0,0,1,1,0,0,0,1,1,1,0,0,1,0,1,0,0,0,1,1,1,0,1,0,0,0,0,1,1,0,1,0,1,0,0,0,1,0,1,1,0,0,1,1,0,0,0,1,0,1,1,1,1,1,1,0,0,1,0,1,1,0,1,0,1,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,1,0,0,0,0,1,1,1,1,0,0,1,0,0,0,0,1,1,1,1,0,1,0,0,1,0,0,0,0,0,1,1,1,0,0,1,1,1,0,0,0,0,0,0,0,1,1,1,0,0,1,0,1,0,0,0,1,0,0,0,0,0,1,0,1,0,1,1,0,1,0,0,1,0,1,0,0,1,0,1,1,0,1,0,1,0,1,0,0,1,0,1,0,0,0,0,0,0,1,0,1,1,1,0,0,1,1,1,1,0,1,0,1,1,0,0,0,0,0,1,1,1,1,1,0,0,0,0,0,0,1,1,0,0,1,0,1,1,1,0,0,1,0,1,1,1,1,0,0,0,1,0,1,0,1,0,0,1,1,1,0,0,1,0,0,1,0,1,1,0,1,1,0,0,1,1,1,0,0,0,1,0,1,1,0,1,1,1,1,1,0,1,1,0,1,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]}`
	for i := 0; i < b.N; i++ {
		prover.Prove([]byte(params))
	}
	b.ReportAllocs()
}

func Benchmark_ProveChacha(b *testing.B) {
	prover.InitAlgorithm(prover.CHACHA20, chachaKey, chachaR1CS)
	b.ResetTimer()
	params := `{"cipher":"chacha20","key":[[0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1],[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]],"nonce":[[0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1],[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]],"counter":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1],"input":[[1,0,0,1,1,0,0,1,0,1,0,0,1,0,0,0,1,1,0,0,0,0,1,0,0,0,1,0,0,0,0,1],[1,1,1,0,1,0,1,1,1,0,0,1,0,0,1,0,1,1,1,1,0,1,0,0,0,1,0,1,1,0,1,1],[1,1,1,0,0,0,1,1,0,0,0,0,0,0,1,1,0,1,0,1,0,0,1,1,1,1,0,1,0,1,0,1],[0,1,1,1,1,0,1,1,0,0,1,0,1,1,0,0,0,0,0,0,1,0,1,1,0,1,0,1,0,1,0,1],[0,0,0,0,1,1,1,1,1,1,1,1,1,0,0,0,0,0,1,1,1,0,0,1,1,1,1,0,0,0,1,1],[0,0,1,0,1,0,1,0,1,1,1,0,1,0,1,1,0,1,1,1,0,0,1,1,0,1,1,0,1,0,0,0],[0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0],[0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0],[0,0,1,0,1,0,0,1,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0],[1,1,0,1,1,0,1,0,0,1,1,0,0,0,1,0,1,0,0,0,0,1,1,0,0,1,0,0,0,0,0,0],[1,0,0,1,0,1,0,0,0,1,0,1,0,0,1,0,0,1,0,0,0,1,1,1,0,1,0,1,1,1,1,1],[0,1,0,0,0,1,1,1,0,1,1,0,1,1,1,0,0,0,1,0,1,0,1,1,1,1,0,0,0,0,1,1],[1,0,0,0,1,1,1,0,1,0,1,0,0,0,1,1,1,0,0,0,0,1,0,0,1,1,0,1,1,1,0,1],[0,1,1,1,1,0,0,1,1,1,0,0,0,1,1,0,1,1,1,0,0,1,0,0,1,0,0,1,1,1,1,1],[0,0,1,0,1,1,1,0,0,1,0,1,0,0,0,1,1,1,0,0,0,0,1,1,0,1,1,1,0,0,1,1],[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]]}`
	for i := 0; i < b.N; i++ {
		prover.Prove([]byte(params))
	}
	b.ReportAllocs()
}

func toUint8(a []int) []uint8 {
	res := make([]uint8, len(a))
	for i, v := range a {
		res[i] = uint8(v)
	}
	return res
}

func fetchFile(keyName string) ([]byte, error) {
	f, err := os.ReadFile("../circuits/generated/" + keyName)
	if err != nil {
		panic(err)
	}
	return f, nil
}
