package main

import (
	"bytes"
	"crypto/rand"
	_ "embed"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/reclaimprotocol/gnark-chacha20/chacha"
	"golang.org/x/crypto/chacha20"
)

import (
	_ "net/http/pprof"
)

//go:embed prove/r1cs
var r1cs_embedded []byte

//go:embed prove/pk
var pk_embedded []byte

func main() {

	go func() {
		http.ListenAndServe("localhost:8088", nil)
	}()
	time.Sleep(time.Second * 10)
	for i := 0; i < 10; i++ {
		err := ProveG16()
		if err != nil {
			log.Fatal("groth16 error:", err)
		}
	}
	time.Sleep(time.Second * 1000)
}

// var r1css = groth16.NewCS(ecc.BN254)
// var pk groth16.ProvingKey

func generateGroth16() error {

	/*fmt.Println("about to read key & circuit")
	r1css = groth16.NewCS(ecc.BN254)
	_, err := r1css.ReadFrom(bytes.NewBuffer(r1cs_embedded))
	if err != nil {
		panic(err)
	}

	pk = groth16.NewProvingKey(ecc.BN254)
	_, err = pk.ReadFrom(bytes.NewBuffer(pk_embedded))
	if err != nil {
		panic(err)
	}
	fmt.Println("read key & circuit")

	bKey := make([]uint8, 32)
	rand.Read(bKey)
	bNonce := make([]uint8, 12)
	rand.Read(bNonce)
	counter := uints.NewU32(1)

	dataBytes := chacha.Blocks * 64
	bPt := make([]byte, dataBytes)
	rand.Read(bPt)
	bCt := make([]byte, dataBytes)

	cipher, err := chacha20.NewUnauthenticatedCipher(bKey, bNonce)
	if err != nil {
		return err
	}

	cipher.SetCounter(1)
	cipher.XORKeyStream(bCt, bPt)

	plaintext := chacha.BytesToUint32BE(bPt)
	ciphertext := chacha.BytesToUint32BE(bCt)

	fmt.Printf("%0X\n", bKey)
	fmt.Printf("%0X\n", bNonce)
	fmt.Printf("%0X\n", bPt)
	fmt.Printf("%0X\n", bCt)

	witness := chacha.Circuit{}
	copy(witness.Key[:], chacha.BytesToUint32LE(bKey))
	copy(witness.Nonce[:], chacha.BytesToUint32LE(bNonce))
	witness.Counter = counter
	copy(witness.In[:], plaintext)
	copy(witness.Out[:], ciphertext)

	wtns, err := frontend.NewWitness(&witness, ecc.BN254.ScalarField())

	proof, err := groth16.Prove(r1css, pk, wtns)

	if err != nil {
		panic(err)
	}
	buf := &bytes.Buffer{}
	_, err = proof.WriteTo(buf)
	if err != nil {
		panic(err)
	}
	res := buf.Bytes()
	fmt.Printf("%0X\n", res)*/

	var circuit chacha.Circuit

	/*f, err := os.Open("f:\\r1cs")
	r1css := groth16.NewCS(ecc.BN254)
	r1css.ReadFrom(f)
	f.Close()

	f1, err := os.Open("f:\\pk")
	pk := groth16.NewProvingKey(ecc.BN254)
	pk.ReadFrom(f1)
	f1.Close()*/

	/*f2, err := os.Open("f:\\vk")
	vk := groth16.NewVerifyingKey(ecc.BN254)
	vk.ReadFrom(f2)
	f2.Close()*/

	/*p := profile.Start()
	_, _ = frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &chacha.Circuit{})
	p.Stop()

	fmt.Println(p.NbConstraints())
	fmt.Println(p.Top())*/

	curve := ecc.BN254.ScalarField()

	r1css, err := frontend.Compile(curve, r1cs.NewBuilder, &circuit)
	if err != nil {
		return err
	}

	fmt.Printf("Blocks: %d, constraints: %d\n", chacha.Blocks, r1css.GetNbConstraints())

	f, err := os.OpenFile("f:\\r1cs", os.O_RDWR|os.O_CREATE, 0777)
	r1css.WriteTo(f)
	f.Close()

	pk, vk, err := groth16.Setup(r1css)
	if err != nil {
		return err
	}

	f2, err := os.OpenFile("f:\\pk", os.O_RDWR|os.O_CREATE, 0777)
	pk.WriteTo(f2)
	f2.Close()

	f3, err := os.OpenFile("f:\\vk", os.O_RDWR|os.O_CREATE, 0777)
	vk.WriteTo(f3)
	f3.Close()

	bKey := make([]uint8, 32)
	rand.Read(bKey)
	bNonce := make([]uint8, 12)
	rand.Read(bNonce)
	counter := uints.NewU32(1)

	dataBytes := chacha.Blocks * 64
	bPt := make([]byte, dataBytes)
	rand.Read(bPt)
	bCt := make([]byte, dataBytes)

	cipher, err := chacha20.NewUnauthenticatedCipher(bKey, bNonce)
	if err != nil {
		return err
	}

	cipher.SetCounter(1)
	cipher.XORKeyStream(bCt, bPt)

	plaintext := chacha.BytesToUint32BE(bPt)
	ciphertext := chacha.BytesToUint32BE(bCt)

	fmt.Printf("%0X\n", bKey)
	fmt.Printf("%0X\n", bNonce)
	fmt.Printf("%0X\n", bPt)
	fmt.Printf("%0X\n", bCt)

	witness := chacha.Circuit{}
	copy(witness.Key[:], chacha.BytesToUint32LE(bKey))
	copy(witness.Nonce[:], chacha.BytesToUint32LE(bNonce))
	witness.Counter = counter
	copy(witness.In[:], plaintext)
	copy(witness.Out[:], ciphertext)
	fmt.Println("witness")
	wtns, err := frontend.NewWitness(&witness, curve)
	fmt.Println("prove")

	proof, err := groth16.Prove(r1css, pk, wtns)
	buf := &bytes.Buffer{}
	_, err = proof.WriteTo(buf)
	if err != nil {
		panic(err)
	}
	res := buf.Bytes()
	fmt.Printf("%0X\n", res)
	/*f3, err := os.OpenFile("f:\\proof", os.O_RDWR|os.O_CREATE, 0777)
	proof.WriteTo(f3)
	f3.Close()*/

	wp, err := frontend.NewWitness(&witness, curve, frontend.PublicOnly())
	err = groth16.Verify(proof, vk, wp)
	fmt.Println("proof ok", err == nil)
	return nil
}

func ProveG16() error {
	key := make([]uint8, 32)
	rand.Read(key)
	nonce := make([]uint8, 12)
	rand.Read(nonce)
	cnt := uints.NewU32(1)

	dataBytes := chacha.Blocks * 64
	bPt := make([]byte, dataBytes)
	rand.Read(bPt)
	bCt := make([]byte, dataBytes)

	cipher, err := chacha20.NewUnauthenticatedCipher(key, nonce)
	if err != nil {
		return err
	}

	cipher.SetCounter(1)
	cipher.XORKeyStream(bCt, bPt)

	plaintext := chacha.BytesToUint32BE(bPt)
	ciphertext := chacha.BytesToUint32BE(bCt)

	r1css := groth16.NewCS(ecc.BN254)
	_, err = r1css.ReadFrom(bytes.NewBuffer(r1cs_embedded))
	if err != nil {
		panic(err)
	}

	pk := groth16.NewProvingKey(ecc.BN254)
	_, err = pk.ReadFrom(bytes.NewBuffer(pk_embedded))
	if err != nil {
		panic(err)
	}

	witness := chacha.Circuit{}
	copy(witness.Key[:], chacha.BytesToUint32LE(key))
	copy(witness.Nonce[:], chacha.BytesToUint32LE(nonce))
	witness.Counter = cnt
	copy(witness.In[:], plaintext)
	copy(witness.Out[:], ciphertext)
	wtns, err := frontend.NewWitness(&witness, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}
	_, err = groth16.Prove(r1css, pk, wtns)
	return err
}
