package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	_ "embed"
	"encoding/binary"
	"fmt"
	"log"
	"sync"
	"unsafe"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	gaes "github.com/reclaimprotocol/gnark-chacha20/aes"
	"github.com/reclaimprotocol/gnark-chacha20/chachaV3"
	"github.com/reclaimprotocol/gnark-chacha20/utils"
	"golang.org/x/crypto/chacha20"
)

// #include <stdlib.h>
import (
	"C"
)

func main() {}

//export Free
func Free(pointer unsafe.Pointer) {
	C.free(pointer)
}

/*//go:embed r1cs
var r1cssChaChaEmbedded []byte

//go:embed r1cs.aes128
var r1cssAES128Embedded []byte

//go:embed r1cs.aes256
var r1cssAES256Embedded []byte*/

//go:embed pk
var pkChaChaEmbedded []byte
var r1cssChaCha constraint.ConstraintSystem
var pkChaCha groth16.ProvingKey
var chachaDone bool

//go:embed pk.aes128
var pkAES128Embedded []byte
var r1cssAES128 constraint.ConstraintSystem
var pkAES128 groth16.ProvingKey
var aes128Done bool

//go:embed pk.aes256
var pkAES256Embedded []byte
var r1cssAES256 constraint.ConstraintSystem
var pkAES256 groth16.ProvingKey
var aes256Done bool

var initChaCha sync.WaitGroup
var initAES128 sync.WaitGroup
var initAES256 sync.WaitGroup

func init() {
	initChaCha.Add(1)
	initAES128.Add(1)
	initAES256.Add(1)
}

var initFunc = sync.OnceFunc(func() {

	if len(pkChaChaEmbedded) == 0 ||
		len(pkAES128Embedded) == 0 ||
		len(pkAES256Embedded) == 0 {
		panic("could not load circuit and proving key")
	}

	fmt.Println("loading ChaCha")
	var err error

	curve := ecc.BN254.ScalarField()

	witnessChaCha := chachaV3.ChaChaCircuit{}
	r1cssChaCha, err = frontend.Compile(curve, r1cs.NewBuilder, &witnessChaCha, frontend.WithCapacity(25000))
	if err != nil {
		panic(err)
	}
	pkChaCha = groth16.NewProvingKey(ecc.BN254)
	_, err = pkChaCha.ReadFrom(bytes.NewBuffer(pkChaChaEmbedded))
	if err != nil {
		panic(err)
	}
	initChaCha.Done()
	chachaDone = true

	fmt.Println("compiling AES128")
	witnessAES128 := gaes.AES128Wrapper{
		Key:        [16]frontend.Variable{},
		Plaintext:  [16]frontend.Variable{},
		Ciphertext: [16]frontend.Variable{},
	}
	r1cssAES128, err = frontend.Compile(curve, r1cs.NewBuilder, &witnessAES128, frontend.WithCapacity(150000))

	if err != nil {
		panic(err)
	}

	pkAES128 = groth16.NewProvingKey(ecc.BN254)
	_, err = pkAES128.ReadFrom(bytes.NewBuffer(pkAES128Embedded))
	if err != nil {
		panic(err)
	}
	initAES128.Done()
	aes128Done = true

	fmt.Println("compiling AES256")
	witnessAES256 := gaes.AES256Wrapper{
		Key:        [32]frontend.Variable{},
		Plaintext:  [16]frontend.Variable{},
		Ciphertext: [16]frontend.Variable{},
	}
	r1cssAES256, err = frontend.Compile(curve, r1cs.NewBuilder, &witnessAES256, frontend.WithCapacity(200000))
	if err != nil {
		panic(err)
	}
	pkAES256 = groth16.NewProvingKey(ecc.BN254)
	_, err = pkAES256.ReadFrom(bytes.NewBuffer(pkAES256Embedded))
	if err != nil {
		panic(err)
	}
	initAES256.Done()
	aes256Done = true
	fmt.Println("Done compiling")
	// PrintMemUsage()
})

//export Init
func Init() {
	go initFunc()
}

//export InitComplete
func InitComplete() bool {
	return chachaDone && aes128Done && aes256Done
}

//export ProveChaCha
func ProveChaCha(cnt []byte, key []byte, nonce []byte, plaintext []byte) (unsafe.Pointer, int) {
	initChaCha.Wait()

	if len(cnt) != 4 {
		log.Panicf("counter length must be 4: %d", len(cnt))
	}
	if len(key) != 32 {
		log.Panicf("key length must be 16: %d", len(key))
	}
	if len(nonce) != 12 {
		log.Panicf("nonce length must be 12: %d", len(nonce))
	}
	if len(plaintext) != 64 {
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
	res := buf.Bytes()
	return C.CBytes(res), len(res)
}

//export ProveAES128
func ProveAES128(cnt, key, nonce, plaintext []byte) (unsafe.Pointer, int) {
	initAES128.Wait()
	if len(cnt) != 4 {
		log.Panicf("counter length must be 4: %d", len(cnt))
	}
	if len(key) != 16 {
		log.Panicf("key length must be 16: %d", len(key))
	}
	if len(nonce) != 12 {
		log.Panicf("nonce length must be 12: %d", len(nonce))
	}
	if len(plaintext) != 16 {
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

	witness := gaes.AES128Wrapper{
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
	res := buf.Bytes()
	return C.CBytes(res), len(res)
}

//export ProveAES256
func ProveAES256(cnt []byte, key []byte, nonce []byte, plaintext []byte) (unsafe.Pointer, int) {
	initAES256.Wait()

	if len(cnt) != 4 {
		log.Panicf("counter length must be 4: %d", len(cnt))
	}
	if len(key) != 32 {
		log.Panicf("key length must be 32: %d", len(key))
	}
	if len(nonce) != 12 {
		log.Panicf("nonce length must be 12: %d", len(nonce))
	}
	if len(plaintext) != 16 {
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

	witness := gaes.AES256Wrapper{
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
	res := buf.Bytes()
	return C.CBytes(res), len(res)
}
