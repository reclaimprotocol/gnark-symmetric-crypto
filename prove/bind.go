package main

import (
	"bytes"
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
	"github.com/consensys/gnark/std/math/uints"
	"github.com/reclaimprotocol/gnark-chacha20/aes"
	"github.com/reclaimprotocol/gnark-chacha20/chacha"
	"github.com/reclaimprotocol/gnark-chacha20/utils"
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

//go:embed pk
var pkChaChaEmbedded []byte
var r1cssChaCha constraint.ConstraintSystem
var pkChaCha groth16.ProvingKey

//go:embed pk.aes128
var pkAES128Embedded []byte
var r1cssAES128 constraint.ConstraintSystem
var pkAES128 groth16.ProvingKey

//go:embed pk.aes256
var pkAES256Embedded []byte
var r1cssAES256 constraint.ConstraintSystem
var pkAES256 groth16.ProvingKey

var initDone sync.WaitGroup

func init() {
	initDone.Add(1)
}

var initFunc = sync.OnceFunc(func() {
	defer initDone.Done()
	if len(pkChaChaEmbedded) == 0 ||
		len(pkAES128Embedded) == 0 ||
		len(pkAES256Embedded) == 0 {
		panic("could not load circuit and proving key")
	}

	fmt.Println("compiling ChaCha")
	var err error
	curve := ecc.BN254.ScalarField()

	witnessChaCha := chacha.ChaChaCircuit{
		Counter: uints.NewU32(0),
		Key:     make([]uints.U32, 8),
		Nonce:   make([]uints.U32, 3),
		In:      make([]uints.U32, 16),
		Out:     make([]uints.U32, 16),
	}
	r1cssChaCha, err = frontend.Compile(curve, r1cs.NewBuilder, &witnessChaCha, frontend.WithCapacity(80000))

	if err != nil {
		panic(err)
	}
	pkChaCha = groth16.NewProvingKey(ecc.BN254)
	_, err = pkChaCha.ReadFrom(bytes.NewBuffer(pkChaChaEmbedded))
	if err != nil {
		panic(err)
	}

	fmt.Println("compiling AES128")
	witnessAES128 := aes.AES128Wrapper{
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

	fmt.Println("compiling AES256")
	witnessAES256 := aes.AES256Wrapper{
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
	fmt.Println("Done compiling")
})

//export Init
func Init() {
	go initFunc()
}

type WitnessChaCha struct {
	Key     []uints.U32
	Counter uints.U32 `gnark:",public"`
	Nonce   []uints.U32
	In      []uints.U32 `gnark:",public"`
	Out     []uints.U32 `gnark:",public"`
}

func (c *WitnessChaCha) Define(api frontend.API) error {
	return nil
}

//export ProveChaCha
func ProveChaCha(cnt []byte, key []byte, nonce []byte, plaintext, ciphertext []byte) (unsafe.Pointer, int) {
	initDone.Wait()
	uplaintext := utils.BytesToUint32BE(plaintext)
	uciphertext := utils.BytesToUint32BE(ciphertext)
	ukey := utils.BytesToUint32LE(key)
	unonce := utils.BytesToUint32LE(nonce)

	witness := WitnessChaCha{
		Counter: uints.NewU32(binary.BigEndian.Uint32(cnt)),
		Key:     make([]uints.U32, len(ukey)),
		Nonce:   make([]uints.U32, len(unonce)),
		In:      make([]uints.U32, len(uplaintext)),
		Out:     make([]uints.U32, len(uciphertext)),
	}
	copy(witness.Key[:], ukey)
	copy(witness.Nonce[:], unonce)
	copy(witness.In[:], uplaintext)
	copy(witness.Out[:], uciphertext)
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

type WitnessAES128 struct {
	Key        [16]frontend.Variable
	Nonce      [12]frontend.Variable
	Counter    frontend.Variable `gnark:",public"`
	Plaintext  [16]frontend.Variable
	Ciphertext [16]frontend.Variable `gnark:",public"`
}

func (c *WitnessAES128) Define(api frontend.API) error {
	return nil
}

//export ProveAES128
func ProveAES128(counter, key, nonce, plaintext, ciphertext []byte) (unsafe.Pointer, int) {
	initDone.Wait()
	if len(counter) != 4 {
		log.Panicf("counter length must be 4: %d", len(counter))
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
	if len(ciphertext) != 16 {
		log.Panicf("ciphertext length must be 16: %d", len(ciphertext))
	}

	witness := WitnessAES128{
		Key:        [16]frontend.Variable{},
		Counter:    binary.BigEndian.Uint32(counter),
		Nonce:      [12]frontend.Variable{},
		Plaintext:  [16]frontend.Variable{},
		Ciphertext: [16]frontend.Variable{},
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

type WitnessAES256 struct {
	Key        [32]frontend.Variable
	Nonce      [12]frontend.Variable
	Counter    frontend.Variable `gnark:",public"`
	Plaintext  [16]frontend.Variable
	Ciphertext [16]frontend.Variable `gnark:",public"`
}

func (c *WitnessAES256) Define(api frontend.API) error {
	return nil
}

//export ProveAES256
func ProveAES256(cnt []byte, key []byte, nonce []byte, plaintext, ciphertext []byte) (unsafe.Pointer, int) {
	initDone.Wait()
	witness := WitnessAES256{
		Key:        [32]frontend.Variable{},
		Counter:    binary.BigEndian.Uint32(cnt),
		Nonce:      [12]frontend.Variable{},
		Plaintext:  [16]frontend.Variable{},
		Ciphertext: [16]frontend.Variable{},
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
