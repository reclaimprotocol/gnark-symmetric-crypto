package circuits

import "C"
import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	aes2 "gnark-symmetric-crypto/circuits/aes"
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
	Prove(r1cs constraint.ConstraintSystem, pk groth16.ProvingKey, cnt []byte, key []byte, nonce []byte, plaintext []byte) (proof, ciphertext []byte)
}

type ChaChaProver struct {
}

func (*ChaChaProver) Prove(r1cssChaCha constraint.ConstraintSystem, pkChaCha groth16.ProvingKey, cnt []byte, key []byte, nonce []byte, plaintext []byte) ([]byte, []byte) {

	if len(cnt) != 4 {
		log.Panicf("counter length must be 4: %d", len(cnt))
	}
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

	cipher.SetCounter(binary.BigEndian.Uint32(cnt))
	cipher.XORKeyStream(ciphertext, plaintext)

	uplaintext := utils.BytesToUint32BERaw(plaintext)
	uciphertext := utils.BytesToUint32BERaw(ciphertext)
	ukey := utils.BytesToUint32LERaw(key)
	unonce := utils.BytesToUint32LERaw(nonce)

	witness := chachaV3.ChaChaCircuit{}
	copy(witness.Key[:], utils.UintsToBits(ukey))
	copy(witness.Nonce[:], utils.UintsToBits(unonce))
	witness.Counter = utils.Uint32ToBits(binary.BigEndian.Uint32(cnt))
	copy(witness.In[:], utils.UintsToBits(uplaintext))
	copy(witness.Out[:], utils.UintsToBits(uciphertext))

	wtns, err := frontend.NewWitness(&witness, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}
	gProof, err := groth16.Prove(r1cssChaCha, pkChaCha, wtns)
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

type AES128Prover struct {
}

func (*AES128Prover) Prove(r1cssAES128 constraint.ConstraintSystem, pkAES128 groth16.ProvingKey, cnt []byte, key []byte, nonce []byte, plaintext []byte) ([]byte, []byte) {
	if len(cnt) != 4 {
		log.Panicf("counter length must be 4: %d", len(cnt))
	}
	if len(key) != 16 {
		log.Panicf("key length must be 16: %d", len(key))
	}
	if len(nonce) != 12 {
		log.Panicf("nonce length must be 12: %d", len(nonce))
	}
	if len(plaintext) != 16*aes2.BLOCKS {
		log.Panicf("plaintext length must be 16: %d", len(plaintext))
	}

	// calculate ciphertext ourselves
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	cipher := cipher.NewCTR(block, append(nonce, cnt...))
	ciphertext := make([]byte, len(plaintext))
	cipher.XORKeyStream(ciphertext, plaintext)

	witness := aes2.AES128Wrapper{
		Counter: binary.BigEndian.Uint32(cnt),
	}

	for i := 0; i < len(key); i++ {
		witness.Key[i] = key[i]
	}
	for i := 0; i < len(nonce); i++ {
		witness.Nonce[i] = nonce[i]
	}
	for i := 0; i < len(plaintext); i++ {
		witness.Plaintext[i] = plaintext[i]
	}
	for i := 0; i < len(ciphertext); i++ {
		witness.Ciphertext[i] = ciphertext[i]
	}

	wtns, err := frontend.NewWitness(&witness, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}
	gProof, err := groth16.Prove(r1cssAES128, pkAES128, wtns)
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

type AES256Prover struct {
}

func (*AES256Prover) Prove(r1cssAES256 constraint.ConstraintSystem, pkAES256 groth16.ProvingKey, cnt []byte, key []byte, nonce []byte, plaintext []byte) ([]byte, []byte) {

	if len(cnt) != 4 {
		log.Panicf("counter length must be 4: %d", len(cnt))
	}
	if len(key) != 32 {
		log.Panicf("key length must be 32: %d", len(key))
	}
	if len(nonce) != 12 {
		log.Panicf("nonce length must be 12: %d", len(nonce))
	}
	if len(plaintext) != 16*aes2.BLOCKS {
		log.Panicf("plaintext length must be 16: %d", len(plaintext))
	}

	// calculate ciphertext ourselves
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	cipher := cipher.NewCTR(block, append(nonce, cnt...))
	ciphertext := make([]byte, len(plaintext))
	cipher.XORKeyStream(ciphertext, plaintext)

	witness := aes2.AES256Wrapper{
		Counter: binary.BigEndian.Uint32(cnt),
	}
	for i := 0; i < len(key); i++ {
		witness.Key[i] = key[i]
	}
	for i := 0; i < len(nonce); i++ {
		witness.Nonce[i] = nonce[i]
	}
	for i := 0; i < len(plaintext); i++ {
		witness.Plaintext[i] = plaintext[i]
	}

	for i := 0; i < len(ciphertext); i++ {
		witness.Ciphertext[i] = ciphertext[i]
	}

	wtns, err := frontend.NewWitness(&witness, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}
	gProof, err := groth16.Prove(r1cssAES256, pkAES256, wtns)
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
