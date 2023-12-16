package main

import (
	"fmt"
	"log"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/profile"
	"github.com/reclaimprotocol/gnark-chacha20/chacha"
)

func main() {
	err := generateGroth16()
	if err != nil {
		log.Fatal("groth16 error:", err)
	}
}

func generateGroth16() error {
	// var circuit chacha.Circuit

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

	p := profile.Start()
	_, _ = frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &chacha.Circuit{})
	p.Stop()

	fmt.Println(p.NbConstraints())
	fmt.Println(p.Top())
	/*r1css, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		return err
	}*/

	/*f, err := os.OpenFile("f:\\r1cs", os.O_RDWR|os.O_CREATE, 0777)
	r1css.WriteTo(f)
	f.Close()*/

	/*pk, vk, err := groth16.Setup(r1css)
	if err != nil {
		return err
	}*/

	/*f2, err := os.OpenFile("f:\\pk", os.O_RDWR|os.O_CREATE, 0777)
	pk.WriteTo(f2)
	f2.Close()

	f3, err := os.OpenFile("f:\\vk", os.O_RDWR|os.O_CREATE, 0777)
	vk.WriteTo(f3)
	f3.Close()*/

	/*bKey := make([]uint8, 32)
	rand.Read(bKey)
	bNonce := make([]uint8, 12)
	rand.Read(bNonce)
	counter := uints.NewU32(1)

	bytes := chacha.Blocks * 64
	bPt := make([]byte, bytes)
	rand.Read(bPt)
	bCt := make([]byte, bytes)

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

	f3, err := os.OpenFile("f:\\proof", os.O_RDWR|os.O_CREATE, 0777)
	proof.WriteTo(f3)
	f3.Close()

	/*wp, err := frontend.NewWitness(&witness, ecc.BN254.ScalarField(), frontend.PublicOnly())
	err = groth16.Verify(proof, vk, wp)*/
	return nil
}
