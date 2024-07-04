package circuits

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"testing"
	"unsafe"

	"github.com/consensys/gnark/test"
	"golang.org/x/crypto/chacha20"
)

func TestProve(t *testing.T) {
	assert := test.NewAssert(t)

	InitFunc()
	bKey := []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f}

	bNonce := []byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00}

	bPt := make([]byte, 64)
	rand.Read(bPt)
	bCt := make([]byte, 64)

	cipher, err := chacha20.NewUnauthenticatedCipher(bKey, bNonce)
	assert.NoError(err)

	cipher.SetCounter(1)
	cipher.XORKeyStream(bCt, bPt)

	params := &InputParams{
		Name:      "chacha20",
		Key:       hex.EncodeToString(bKey),
		Nonce:     hex.EncodeToString(bNonce),
		Counter:   1,
		Plaintext: hex.EncodeToString(bPt),
	}

	bParams, err := json.Marshal(&params)
	assert.NoError(err)
	res, resLen := Prove(bParams)
	assert.True(resLen > 0)

	h := reflect.SliceHeader{
		Data: uintptr(res),
		Len:  resLen,
		Cap:  resLen,
	}
	buf := *(*[]byte)(unsafe.Pointer(&h))

	var proveResult *OutputParams
	err = json.Unmarshal(buf, &proveResult)
	assert.NoError(err)

	verifyParams := &InputVerifyParams{
		Name:       "chacha20",
		Proof:      proveResult.Proof,
		Plaintext:  params.Plaintext,
		Ciphertext: proveResult.Ciphertext,
	}

	bverifyParams, err := json.Marshal(verifyParams)
	assert.NoError(err)
	assert.True(Verify(bverifyParams))
}
