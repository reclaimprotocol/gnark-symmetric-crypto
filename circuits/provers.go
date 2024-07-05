package circuits

import "C"
import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	gaes "gnark-symmetric-crypto/circuits/aes"
	"gnark-symmetric-crypto/circuits/chachaV3"
	"gnark-symmetric-crypto/utils"
	"log"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"golang.org/x/crypto/chacha20"
)

type Prover interface {
	Prove(key []byte, nonce []byte, counter uint32, plaintext []byte) (proof, ciphertext []byte)
}

type ChaChaProver struct {
	r1cs constraint.ConstraintSystem
	pk   groth16.ProvingKey
}

func (cp *ChaChaProver) Prove(key []byte, nonce []byte, counter uint32, plaintext []byte) ([]byte, []byte) {

	if len(key) != 32 {
		log.Panicf("key length must be 16: %d", len(key))
	}
	if len(nonce) != 12 {
		log.Panicf("nonce length must be 12: %d", len(nonce))
	}
	if len(plaintext) != 64*chachaV3.Blocks {
		log.Panicf("plaintext length must be 16: %d", len(plaintext))
	}

	// calculate ciphertext ourselves

	ciphertext := make([]byte, len(plaintext))
	cipher, err := chacha20.NewUnauthenticatedCipher(key, nonce)
	if err != nil {
		panic(err)
	}

	cipher.SetCounter(counter)
	cipher.XORKeyStream(ciphertext, plaintext)

	uplaintext := utils.BytesToUint32BERaw(plaintext)
	uciphertext := utils.BytesToUint32BERaw(ciphertext)
	ukey := utils.BytesToUint32LERaw(key)
	unonce := utils.BytesToUint32LERaw(nonce)

	witness := chachaV3.ChaChaCircuit{}
	copy(witness.Key[:], utils.UintsToBits(ukey))
	copy(witness.Nonce[:], utils.UintsToBits(unonce))
	witness.Counter = utils.Uint32ToBits(counter)
	copy(witness.In[:], utils.UintsToBits(uplaintext))
	copy(witness.Out[:], utils.UintsToBits(uciphertext))

	wtns, err := frontend.NewWitness(&witness, ecc.BN254.ScalarField())
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
	return buf.Bytes(), ciphertext
}

type AESProver struct {
	r1cs constraint.ConstraintSystem
	pk   groth16.ProvingKey
}

func (ap *AESProver) Prove(key []byte, nonce []byte, counter uint32, plaintext []byte) ([]byte, []byte) {

	if len(key) != 32 && len(key) != 16 {
		log.Panicf("key length must be 16 or 32: %d", len(key))
	}
	if len(nonce) != 12 {
		log.Panicf("nonce length must be 12: %d", len(nonce))
	}
	if len(plaintext) != 16*gaes.BLOCKS {
		log.Panicf("plaintext length must be %d: %d", 16*gaes.BLOCKS, len(plaintext))
	}

	// calculate ciphertext ourselves
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	cipher := cipher.NewCTR(block, append(nonce, binary.BigEndian.AppendUint32(nil, counter)...))
	ciphertext := make([]byte, len(plaintext))
	cipher.XORKeyStream(ciphertext, plaintext)

	wrapper := gaes.AESWrapper{
		Key: make([]frontend.Variable, len(key)),
	}

	wrapper.Counter = counter
	for i := 0; i < len(key); i++ {
		wrapper.Key[i] = key[i]
	}
	for i := 0; i < len(nonce); i++ {
		wrapper.Nonce[i] = nonce[i]
	}
	for i := 0; i < len(plaintext); i++ {
		wrapper.Plaintext[i] = plaintext[i]
	}

	for i := 0; i < len(ciphertext); i++ {
		wrapper.Ciphertext[i] = ciphertext[i]
	}

	var circuit frontend.Circuit
	if len(key) == 16 {
		circuit = &gaes.AES128Wrapper{AESWrapper: wrapper}
	} else {
		circuit = &gaes.AES256Wrapper{AESWrapper: wrapper}
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
	return buf.Bytes(), ciphertext
}
