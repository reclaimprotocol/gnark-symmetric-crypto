package main

import (
	"bytes"
	"crypto/rand"
	aes2 "gnark-symmetric-crypto/circuits/aes"
	"gnark-symmetric-crypto/circuits/chacha"
	"gnark-symmetric-crypto/circuits/chachaV3"
	"time"

	// _ "embed"
	"fmt"
	"os"

	"gnark-symmetric-crypto/utils"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/math/uints"

	"golang.org/x/crypto/chacha20"
)

// /go:embed prove/r1cs
var r1cs_embedded []byte

// /go:embed prove/pk
var pk_embedded []byte

type Witness struct {
	Key     []uints.U32
	Counter uints.U32 `gnark:",public"`
	Nonce   []uints.U32
	In      []uints.U32 `gnark:",public"`
	Out     []uints.U32 `gnark:",public"`
}

func (c *Witness) Define(api frontend.API) error {
	return nil
}

func main() {

	/*go func() {
		http.ListenAndServe("localhost:8088", nil)
	}()*/
	/*time.Sleep(time.Second * 10)
	for i := 0; i < 10; i++ {
		err := ProveG16()
		if err != nil {
			log.Fatal("groth16 error:", err)
		}
	}
	time.Sleep(time.Second * 1000)*/
	// generateGroth16()
	// trySerialize()

	// generateChaCha()
	generateChaChaV3()
	generateAES128()
	generateAES256()
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

	witness := chacha.ChaChaCircuit{}
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

	/*f, err := os.Open("circuits/generated/r1cs")
	r1css := groth16.NewCS(ecc.BN254)
	r1css.ReadFrom(f)
	f.Close()

	f1, err := os.Open("circuits/generated/pk")
	pk := groth16.NewProvingKey(ecc.BN254)
	pk.ReadFrom(f1)
	f1.Close()*/

	/*f2, err := os.Open("verifier/generated/vk")
	vk := groth16.NewVerifyingKey(ecc.BN254)
	vk.ReadFrom(f2)
	f2.Close()*/

	/*p := profile.Start()
	_, _ = frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &chacha.ChaChaCircuit{})
	p.Stop()

	fmt.Println(p.NbConstraints())
	fmt.Println(p.Top())*/

	bKey := make([]uint8, 32)
	rand.Read(bKey)
	bNonce := make([]uint8, 12)
	rand.Read(bNonce)

	cnt := uint32(1)

	counter := uints.NewU32(cnt)

	dataBytes := chacha.Blocks * 64
	bPt := make([]byte, dataBytes)
	rand.Read(bPt)
	bCt := make([]byte, dataBytes)

	cipher, err := chacha20.NewUnauthenticatedCipher(bKey, bNonce)
	if err != nil {
		return err
	}

	cipher.SetCounter(cnt)
	cipher.XORKeyStream(bCt, bPt)

	plaintext := utils.BytesToUint32BE(bPt)
	ciphertext := utils.BytesToUint32BE(bCt)
	key := utils.BytesToUint32LE(bKey)
	nonce := utils.BytesToUint32LE(bNonce)

	fmt.Printf("%0X\n", bKey)
	fmt.Printf("%0X\n", bNonce)
	fmt.Printf("%0X\n", bPt)
	fmt.Printf("%0X\n", bCt)

	witness := chacha.ChaChaCircuit{}

	curve := ecc.BN254.ScalarField()
	t := time.Now()
	r1css, err := frontend.Compile(curve, r1cs.NewBuilder, &witness, frontend.WithCompressThreshold(10), frontend.WithCapacity(500000))
	if err != nil {
		return err
	}
	fmt.Println("compile took ", time.Since(t))

	fmt.Printf("Blocks: %d, constraints: %d\n", chacha.Blocks, r1css.GetNbConstraints())

	os.Remove("circuits/generated/r1cs")
	os.Remove("circuits/generated/pk")
	os.Remove("verifier/generated/vk")
	f, err := os.OpenFile("circuits/generated/r1cs", os.O_RDWR|os.O_CREATE, 0777)
	r1css.WriteTo(f)
	f.Close()

	pk1, vk1, err := groth16.Setup(r1css)
	if err != nil {
		return err
	}

	f2, err := os.OpenFile("circuits/generated/pk", os.O_RDWR|os.O_CREATE, 0777)
	pk1.WriteTo(f2)
	f2.Close()

	f3, err := os.OpenFile("verifier/generated/vk", os.O_RDWR|os.O_CREATE, 0777)
	vk1.WriteTo(f3)
	f3.Close()

	r1css = groth16.NewCS(ecc.BN254)
	f, err = os.OpenFile("circuits/generated/r1cs", os.O_RDONLY, 0777)
	_, err = r1css.ReadFrom(f)
	if err != nil {
		panic(err)
	}
	f.Close()

	fmt.Println("constraints: ", r1css.GetNbConstraints())
	witness = chacha.ChaChaCircuit{}

	copy(witness.Key[:], key)
	copy(witness.Nonce[:], nonce)
	witness.Counter = counter
	copy(witness.In[:], plaintext)
	copy(witness.Out[:], ciphertext)

	fmt.Println("witness")
	wtns, err := frontend.NewWitness(&witness, curve)
	if err != nil {
		panic(err)
	}
	fmt.Println("loading proving key")
	fpk, _ := os.OpenFile("circuits/generated/pk", os.O_RDONLY, 0777)
	pk := groth16.NewProvingKey(ecc.BN254)
	pk.ReadFrom(fpk)
	fpk.Close()

	fmt.Println("Proving")
	proof, err := groth16.Prove(r1css, pk, wtns)
	buf := &bytes.Buffer{}
	_, err = proof.WriteTo(buf)
	if err != nil {
		panic(err)
	}
	res := buf.Bytes()
	fmt.Printf("%0X\n", res)
	/*f3, err := os.OpenFile("circuits/generated/proof", os.O_RDWR|os.O_CREATE, 0777)
	proof.WriteTo(f3)
	f3.Close()*/

	witness = chacha.ChaChaCircuit{}
	witness.Counter = counter
	copy(witness.In[:], plaintext)
	copy(witness.Out[:], ciphertext)

	wp, err := frontend.NewWitness(&witness, curve, frontend.PublicOnly())
	fvk, _ := os.OpenFile("verifier/generated/vk", os.O_RDONLY, 0777)
	vk := groth16.NewVerifyingKey(ecc.BN254)
	vk.ReadFrom(fvk)
	fvk.Close()
	err = groth16.Verify(proof, vk, wp)
	fmt.Println("proof ok", err == nil)
	return nil
}

func generateChaCha() {
	curve := ecc.BN254.ScalarField()

	witness := chacha.ChaChaCircuit{}

	t := time.Now()
	r1css, err := frontend.Compile(curve, r1cs.NewBuilder, &witness)
	if err != nil {
		panic(err)
	}
	fmt.Println("compile took ", time.Since(t))

	fmt.Printf("Blocks: %d, constraints: %d\n", chacha.Blocks, r1css.GetNbConstraints())

	os.Remove("circuits/generated/r1cs")
	os.Remove("circuits/generated/pk")
	os.Remove("verifier/generated/vk")
	f, err := os.OpenFile("circuits/generated/r1cs", os.O_RDWR|os.O_CREATE, 0777)
	r1css.WriteTo(f)
	f.Close()

	pk1, vk1, err := groth16.Setup(r1css)
	if err != nil {
		panic(err)
	}

	f2, err := os.OpenFile("circuits/generated/pk", os.O_RDWR|os.O_CREATE, 0777)
	pk1.WriteTo(f2)
	f2.Close()

	f3, err := os.OpenFile("verifier/generated/vk", os.O_RDWR|os.O_CREATE, 0777)
	vk1.WriteTo(f3)
	f3.Close()
}

func generateChaChaV3() {
	curve := ecc.BN254.ScalarField()

	witness := chachaV3.ChaChaCircuit{}

	t := time.Now()
	r1css, err := frontend.Compile(curve, r1cs.NewBuilder, &witness)
	if err != nil {
		panic(err)
	}
	fmt.Println("compile took ", time.Since(t))

	fmt.Printf("Blocks: %d, constraints: %d\n", chachaV3.Blocks, r1css.GetNbConstraints())

	os.Remove("circuits/generated/r1cs.bits")
	os.Remove("circuits/generated/pk.bits")
	os.Remove("verifier/generated/vk.bits")
	f, err := os.OpenFile("circuits/generated/r1cs.bits", os.O_RDWR|os.O_CREATE, 0777)
	r1css.WriteTo(f)
	f.Close()

	pk1, vk1, err := groth16.Setup(r1css)
	if err != nil {
		panic(err)
	}

	f2, err := os.OpenFile("circuits/generated/pk.bits", os.O_RDWR|os.O_CREATE, 0777)
	pk1.WriteTo(f2)
	f2.Close()

	f3, err := os.OpenFile("verifier/generated/vk.bits", os.O_RDWR|os.O_CREATE, 0777)
	vk1.WriteTo(f3)
	f3.Close()
}

func generateAES128() {
	curve := ecc.BN254.ScalarField()

	witness := aes2.AES128Wrapper{
		AESWrapper: aes2.AESWrapper{
			Key: make([]frontend.Variable, 16),
		},
	}

	t := time.Now()
	r1css, err := frontend.Compile(curve, r1cs.NewBuilder, &witness)
	if err != nil {
		panic(err)
	}
	fmt.Println("compile took ", time.Since(t))

	fmt.Printf("constraints: %d\n", r1css.GetNbConstraints())

	os.Remove("circuits/generated/r1cs.aes128")
	os.Remove("circuits/generated/pk.aes128")
	os.Remove("verifier/generated/vk.aes128")
	f, err := os.OpenFile("circuits/generated/r1cs.aes128", os.O_RDWR|os.O_CREATE, 0777)
	r1css.WriteTo(f)
	f.Close()

	pk1, vk1, err := groth16.Setup(r1css)
	if err != nil {
		panic(err)
	}

	f2, err := os.OpenFile("circuits/generated/pk.aes128", os.O_RDWR|os.O_CREATE, 0777)
	pk1.WriteTo(f2)
	f2.Close()

	f3, err := os.OpenFile("verifier/generated/vk.aes128", os.O_RDWR|os.O_CREATE, 0777)
	vk1.WriteTo(f3)
	f3.Close()
}

func generateAES256() {
	curve := ecc.BN254.ScalarField()

	witness := aes2.AES256Wrapper{
		AESWrapper: aes2.AESWrapper{
			Key: make([]frontend.Variable, 32),
		},
	}

	t := time.Now()
	r1css, err := frontend.Compile(curve, r1cs.NewBuilder, &witness)
	if err != nil {
		panic(err)
	}
	fmt.Println("compile took ", time.Since(t))

	fmt.Printf("constraints: %d\n", r1css.GetNbConstraints())

	os.Remove("circuits/generated/r1cs.aes256")
	os.Remove("circuits/generated/pk.aes256")
	os.Remove("verifier/generated/vk.aes256")
	f, err := os.OpenFile("circuits/generated/r1cs.aes256", os.O_RDWR|os.O_CREATE, 0777)
	r1css.WriteTo(f)
	f.Close()

	pk1, vk1, err := groth16.Setup(r1css)
	if err != nil {
		panic(err)
	}

	f2, err := os.OpenFile("circuits/generated/pk.aes256", os.O_RDWR|os.O_CREATE, 0777)
	pk1.WriteTo(f2)
	f2.Close()

	f3, err := os.OpenFile("verifier/generated/vk.aes256", os.O_RDWR|os.O_CREATE, 0777)
	vk1.WriteTo(f3)
	f3.Close()
}