package circuits

import "C"
import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/json"
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
	ProveChaCha(key [][]uint8, nonce [][]uint8, counter []uint8, plaintext [][]uint8) (proof []byte, ciphertext []uint8)
	ProveAES(key []uint8, nonce []uint8, counter []uint8, plaintext []uint8) (proof []byte, ciphertext []uint8)
}

type ChaChaProver struct {
	r1cs constraint.ConstraintSystem
	pk   groth16.ProvingKey
}

func (cp *ChaChaProver) ProveAES(_ []uint8, _ []uint8, _ []uint8, _ []uint8) (proof []byte, ciphertext []uint8) {
	panic("not implemented")
}

func (cp *ChaChaProver) ProveChaCha(key [][]uint8, nonce [][]uint8, counter []uint8, plaintext [][]uint8) (proof []byte, ct []uint8) {

	if len(key) != 8 {
		log.Panicf("key length must be 32: %d", len(key))
	}
	if len(nonce) != 3 {
		log.Panicf("nonce length must be 12: %d", len(nonce))
	}
	if len(plaintext) != 16 {
		log.Panicf("plaintext length must be 64: %d", len(plaintext))
	}

	// calculate ciphertext ourselves

	bKey := utils.BitsToBytesLE(key)
	bNonce := utils.BitsToBytesLE(nonce)

	bPlaintext := utils.BitsToBytesLE(plaintext)
	bCiphertext := make([]byte, len(bPlaintext))

	ctr, err := chacha20.NewUnauthenticatedCipher(bKey, bNonce)
	if err != nil {
		panic(err)
	}

	bCounter := utils.BitsToBytes32LE(counter)
	nCounter := binary.LittleEndian.Uint32(bCounter)

	ctr.SetCounter(nCounter)
	ctr.XORKeyStream(bCiphertext, bPlaintext)

	uciphertext := utils.BytesToUint32BERaw(bCiphertext)
	ciphertext := utils.UintsToBits(uciphertext)

	ct = make([]uint8, len(ciphertext)*32)
	// convert to LE for compatibility with witness-sdk
	for i := 0; i < len(ciphertext); i++ {
		for j := 0; j < 4; j++ {
			for k := 0; k < 8; k++ {
				bit := uint8((ciphertext[i][j*8+(7-k)]).(uint))
				ct[i*32+j*8+k] = bit
			}
		}
	}

	witness := &chachaV3.ChaChaCircuit{}

	for i := 0; i < len(witness.Key); i++ {
		for j := 0; j < len(witness.Key[i]); j++ {
			witness.Key[i][j] = key[i][31-j]
		}
	}

	for i := 0; i < len(witness.Nonce); i++ {
		for j := 0; j < len(witness.Nonce[i]); j++ {
			witness.Nonce[i][j] = nonce[i][31-j]
		}
	}

	for i := 0; i < len(witness.Counter); i++ {
		witness.Counter[i] = counter[31-i]
	}

	for i := 0; i < len(witness.In); i++ {
		for j := 0; j < len(witness.In[i]); j++ {
			witness.In[i][j] = plaintext[i][(j/8)*8+(7-j%8)]
		}
	}

	for i := 0; i < len(witness.Out); i++ {
		for j := 0; j < len(witness.Out[i]); j++ {
			witness.Out[i][j] = ciphertext[i][j]
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
	return buf.Bytes(), ct
}

type AESProver struct {
	r1cs constraint.ConstraintSystem
	pk   groth16.ProvingKey
}

func (ap *AESProver) ProveChaCha(_ [][]uint8, _ [][]uint8, _ []uint8, _ [][]uint8) (proof []byte, ciphertext []uint8) {
	panic("not implemented")
}
func (ap *AESProver) ProveAES(key []uint8, nonce []uint8, counter []uint8, plaintext []uint8) (proof []byte, ct []uint8) {

	if len(key) != 256 && len(key) != 128 {
		log.Panicf("key length must be 16 or 32: %d", len(key))
	}
	if len(nonce) != 96 {
		log.Panicf("nonce length must be 12: %d", len(nonce))
	}
	if len(plaintext) != 512 {
		log.Panicf("plaintext length must be 64: %d", len(plaintext))
	}

	var proofs [][]byte
	var ciphertexts []byte
	bKey := utils.BitsToBytesBE(key)
	bNonce := utils.BitsToBytesBE(nonce)

	bPlaintext := utils.BitsToBytesBE(plaintext)

	bCounter := utils.BitsToBytesBE(counter)
	nCounter := binary.BigEndian.Uint32(bCounter)

	// split plaintext into 4 blocks and prove them separately
	for chunk := 0; chunk < 4; chunk++ {
		// calculate ciphertext ourselves

		block, err := aes.NewCipher(bKey)
		if err != nil {
			panic(err)
		}

		bPlaintextChunk := bPlaintext[chunk*16 : chunk*16+16]
		bCiphertextChunk := make([]byte, len(bPlaintextChunk))

		ctr := cipher.NewCTR(block, append(bNonce, binary.BigEndian.AppendUint32(nil, nCounter+uint32(chunk))...))
		ctr.XORKeyStream(bCiphertextChunk, bPlaintextChunk)

		wrapper := gaes.AESWrapper{
			Key: make([]frontend.Variable, len(bKey)),
		}

		wrapper.Counter = nCounter + uint32(chunk)
		for i := 0; i < len(bKey); i++ {
			wrapper.Key[i] = bKey[i]
		}
		for i := 0; i < len(bNonce); i++ {
			wrapper.Nonce[i] = bNonce[i]
		}
		for i := 0; i < len(bPlaintextChunk); i++ {
			wrapper.Plaintext[i] = bPlaintextChunk[i]
		}

		for i := 0; i < len(bCiphertextChunk); i++ {
			wrapper.Ciphertext[i] = bCiphertextChunk[i]
		}

		var circuit frontend.Circuit
		if len(bKey) == 16 {
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

		ciphertexts = append(ciphertexts, bCiphertextChunk...)
		proofs = append(proofs, buf.Bytes())
	}

	bProofs, err := json.Marshal(proofs)
	if err != nil {
		panic(err)
	}

	return bProofs, utils.BytesToBitsBE(ciphertexts)
}
