package impl

import "C"
import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"gnark-symmetric-crypto/utils"
	"log"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std"
	"golang.org/x/crypto/chacha20"
)

func init() {
	std.RegisterHints()
}

const BITS_PER_WORD = 32
const BLOCKS = 1
const AES_BLOCKS = 4

type ChaChaCircuit struct {
	Key     [8][BITS_PER_WORD]frontend.Variable
	Counter [BITS_PER_WORD]frontend.Variable
	Nonce   [3][BITS_PER_WORD]frontend.Variable
	In      [16 * BLOCKS][BITS_PER_WORD]frontend.Variable `gnark:",public"`
	Out     [16 * BLOCKS][BITS_PER_WORD]frontend.Variable `gnark:",public"`
}

func (c *ChaChaCircuit) Define(_ frontend.API) error {
	return nil
}

type AESWrapper struct {
	Key     []frontend.Variable
	Nonce   [12]frontend.Variable
	Counter frontend.Variable
	Input   [AES_BLOCKS * 16]frontend.Variable `gnark:",public"`
	Output  [AES_BLOCKS * 16]frontend.Variable `gnark:",public"`
}

func (circuit *AESWrapper) Define(_ frontend.API) error {
	return nil
}

type InputParams struct {
	Cipher  string  `json:"cipher"`
	Key     []uint8 `json:"key"`
	Nonce   []uint8 `json:"nonce"`
	Counter uint32  `json:"counter"`
	Input   []uint8 `json:"input"` // usually it's redacted ciphertext
}

type Prover interface {
	SetParams(r1cs constraint.ConstraintSystem, pk groth16.ProvingKey)
	Prove(params *InputParams) (proof []byte, output []uint8)
}

type baseProver struct {
	r1cs constraint.ConstraintSystem
	pk   groth16.ProvingKey
}

type ChaChaProver struct {
	baseProver
}

func (cp *ChaChaProver) SetParams(r1cs constraint.ConstraintSystem, pk groth16.ProvingKey) {
	cp.r1cs = r1cs
	cp.pk = pk
}
func (cp *ChaChaProver) proveChaCha(key []uint8, nonce []uint8, counter uint32, input []uint8) (proof []byte, output []uint8) {

	if len(key) != 32 {
		log.Panicf("key length must be 32: %d", len(key))
	}
	if len(nonce) != 12 {
		log.Panicf("nonce length must be 12: %d", len(nonce))
	}
	if len(input) != 64 {
		log.Panicf("input length must be 64: %d", len(input))
	}

	// calculate ciphertext ourselves

	output = make([]byte, len(input))

	ctr, err := chacha20.NewUnauthenticatedCipher(key, nonce)
	if err != nil {
		panic(err)
	}

	ctr.SetCounter(counter)
	ctr.XORKeyStream(output, input)

	// convert input values to bits preserving byte order

	// plaintext & ciphertext are in BE order
	bInput := utils.BytesToUint32BEBits(input)
	bOutput := utils.BytesToUint32BEBits(output)

	// everything else in LE order
	bKey := utils.BytesToUint32LEBits(key)
	bNonce := utils.BytesToUint32LEBits(nonce)
	bCounter := utils.Uint32ToBits(counter)

	witness := &ChaChaCircuit{}

	for i := 0; i < len(witness.Key); i++ {
		for j := 0; j < len(witness.Key[i]); j++ {
			witness.Key[i][j] = bKey[i][j]
		}
	}

	for i := 0; i < len(witness.Nonce); i++ {
		for j := 0; j < len(witness.Nonce[i]); j++ {
			witness.Nonce[i][j] = bNonce[i][j]
		}
	}

	for i := 0; i < len(witness.Counter); i++ {
		witness.Counter[i] = bCounter[i]
	}

	for i := 0; i < len(witness.In); i++ {
		for j := 0; j < len(witness.In[i]); j++ {
			witness.In[i][j] = bInput[i][j]
		}
	}

	for i := 0; i < len(witness.Out); i++ {
		for j := 0; j < len(witness.Out[i]); j++ {
			witness.Out[i][j] = bOutput[i][j]
		}
	}

	wtns, err := frontend.NewWitness(witness, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}
	gProof, err := groth16.Prove(cp.r1cs, cp.pk, wtns)
	if err != nil {
		panic(err)
	}
	buf := &bytes.Buffer{}
	_, err = gProof.WriteTo(buf)
	if err != nil {
		panic(err)
	}
	return buf.Bytes(), output
}
func (cp *ChaChaProver) Prove(params *InputParams) (proof []byte, ciphertext []uint8) {

	return cp.proveChaCha(params.Key, params.Nonce, params.Counter, params.Input)
}

type AESProver struct {
	baseProver
}

func (ap *AESProver) SetParams(r1cs constraint.ConstraintSystem, pk groth16.ProvingKey) {
	ap.r1cs = r1cs
	ap.pk = pk
}
func (ap *AESProver) proveAES(key []uint8, nonce []uint8, counter uint32, input []uint8) (proof []byte, output []uint8) {

	if len(key) != 32 && len(key) != 16 {
		log.Panicf("key length must be 16 or 32: %d", len(key))
	}
	if len(nonce) != 12 {
		log.Panicf("nonce length must be 12: %d", len(nonce))
	}
	if len(input) != 64 {
		log.Panicf("input length must be 64: %d", len(input))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	output = make([]byte, len(input))

	ctr := cipher.NewCTR(block, append(nonce, binary.BigEndian.AppendUint32(nil, counter)...))
	ctr.XORKeyStream(output, input)

	circuit := &AESWrapper{
		Key: make([]frontend.Variable, len(key)),
	}

	circuit.Counter = counter
	for i := 0; i < len(key); i++ {
		circuit.Key[i] = key[i]
	}
	for i := 0; i < len(nonce); i++ {
		circuit.Nonce[i] = nonce[i]
	}
	for i := 0; i < len(input); i++ {
		circuit.Input[i] = input[i]
	}
	for i := 0; i < len(output); i++ {
		circuit.Output[i] = output[i]
	}

	wtns, err := frontend.NewWitness(circuit, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}
	gProof, err := groth16.Prove(ap.r1cs, ap.pk, wtns)
	if err != nil {
		panic(err)
	}
	buf := &bytes.Buffer{}
	_, err = gProof.WriteTo(buf)
	if err != nil {
		panic(err)
	}

	return buf.Bytes(), output
}
func (ap *AESProver) Prove(params *InputParams) (proof []byte, output []uint8) {
	return ap.proveAES(params.Key, params.Nonce, params.Counter, params.Input)
}
