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
	"github.com/reclaimprotocol/gnark-chacha20/aes"
	chacha_bits "github.com/reclaimprotocol/gnark-chacha20/chacha-bits"
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

//go:embed pk.aes128
var pkAES128Embedded []byte
var r1cssAES128 constraint.ConstraintSystem
var pkAES128 groth16.ProvingKey

//go:embed pk.aes256
var pkAES256Embedded []byte
var r1cssAES256 constraint.ConstraintSystem
var pkAES256 groth16.ProvingKey

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

	/*r1cssChaCha = groth16.NewCS(ecc.BN254)
	_, err = r1cssChaCha.ReadFrom(bytes.NewBuffer(r1cssChaChaEmbedded))
	if err != nil {
		panic(err)
	}

	PrintMemUsage()

	r1cssAES128 = groth16.NewCS(ecc.BN254)
	_, err = r1cssAES128.ReadFrom(bytes.NewBuffer(r1cssAES128Embedded))
	if err != nil {
		panic(err)
	}
	PrintMemUsage()
	r1cssAES256 = groth16.NewCS(ecc.BN254)
	_, err = r1cssAES256.ReadFrom(bytes.NewBuffer(r1cssAES256Embedded))
	if err != nil {
		panic(err)
	}

	PrintMemUsage()*/
	curve := ecc.BN254.ScalarField()

	witnessChaCha := chacha_bits.ChaChaCircuit{}

	r1cssChaCha, err = frontend.Compile(curve, r1cs.NewBuilder, &witnessChaCha, frontend.WithCapacity(80000))

	if err != nil {
		panic(err)
	}
	pkChaCha = groth16.NewProvingKey(ecc.BN254)
	_, err = pkChaCha.ReadFrom(bytes.NewBuffer(pkChaChaEmbedded))
	if err != nil {
		panic(err)
	}

	initChaCha.Done()
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
	initAES128.Done()
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
	initAES256.Done()
	fmt.Println("Done compiling")
	// PrintMemUsage()
})

//export Init
func Init() {
	go initFunc()
}

/*type WitnessChaCha struct {
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
	initChaCha.Wait()
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
}*/

//export ProveChaCha
func ProveChaCha(cnt []byte, key []byte, nonce []byte, plaintext, ciphertext []byte) (unsafe.Pointer, int) {
	initChaCha.Wait()
	uplaintext := utils.BytesToUint32BERaw(plaintext)
	uciphertext := utils.BytesToUint32BERaw(ciphertext)
	ukey := utils.BytesToUint32LERaw(key)
	unonce := utils.BytesToUint32LERaw(nonce)

	witness := chacha_bits.ChaChaCircuit{}
	copy(witness.Key[:], ukey)
	copy(witness.Nonce[:], unonce)
	witness.Counter = binary.BigEndian.Uint32(cnt)
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

//export ProveAES128
func ProveAES128(cnt, key, nonce, plaintext, ciphertext []byte) (unsafe.Pointer, int) {
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
	if len(ciphertext) != 16 {
		log.Panicf("ciphertext length must be 16: %d", len(ciphertext))
	}

	witness := aes.AES128Wrapper{
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
func ProveAES256(cnt []byte, key []byte, nonce []byte, plaintext, ciphertext []byte) (unsafe.Pointer, int) {
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
	if len(ciphertext) != 16 {
		log.Panicf("ciphertext length must be 16: %d", len(ciphertext))
	}

	witness := aes.AES256Wrapper{
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
	/*os.Remove("heap.prof")
	f, _ := os.OpenFile("heap.prof", os.O_CREATE|os.O_RDWR, 0777)
	defer f.Close()
	pprof.WriteHeapProfile(f)*/
	// PrintMemUsage()
	return C.CBytes(res), len(res)
}

/*func PrintMemUsage() {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	// For info on each, see: https://golang.org/pkg/runtime/#MemStats
	fmt.Printf("Alloc = %v MiB", bToMb(m.Alloc))
	fmt.Printf("\tTotalAlloc = %v MiB", bToMb(m.TotalAlloc))
	fmt.Printf("\tSys = %v MiB", bToMb(m.Sys))
	fmt.Printf("\tNumGC = %v\n", m.NumGC)
}

func bToMb(b uint64) uint64 {
	return b / 1024 / 1024
}*/
