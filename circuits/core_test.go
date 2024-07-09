package circuits

import (
	"testing"

	"github.com/consensys/gnark/test"
)

func TestProveVerifyChacha(t *testing.T) {
	assert := test.NewAssert(t)

	InitFunc()
	/*bKey := make([]byte, 32)
	bNonce := make([]byte, 12)
	bPt := make([]byte, 64)

	rand.Read(bKey)
	rand.Read(bNonce)
	rand.Read(bPt)
	bCt := make([]byte, len(bPt))

	cipher, err := chacha20.NewUnauthenticatedCipher(bKey, bNonce)
	assert.NoError(err)

	cipher.SetCounter(1)
	cipher.XORKeyStream(bCt, bPt)*/

	params := `{"cipher":"chacha20","key":[[0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1],[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]],"nonce":[[0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1],[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]],"counter":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1],"input":[[1,0,0,1,1,0,0,1,0,1,0,0,1,0,0,0,1,1,0,0,0,0,1,0,0,0,1,0,0,0,0,1],[1,1,1,0,1,0,1,1,1,0,0,1,0,0,1,0,1,1,1,1,0,1,0,0,0,1,0,1,1,0,1,1],[1,1,1,0,0,0,1,1,0,0,0,0,0,0,1,1,0,1,0,1,0,0,1,1,1,1,0,1,0,1,0,1],[0,1,1,1,1,0,1,1,0,0,1,0,1,1,0,0,0,0,0,0,1,0,1,1,0,1,0,1,0,1,0,1],[0,0,0,0,1,1,1,1,1,1,1,1,1,0,0,0,0,0,1,1,1,0,0,1,1,1,1,0,0,0,1,1],[0,0,1,0,1,0,1,0,1,1,1,0,1,0,1,1,0,1,1,1,0,0,1,1,0,1,1,0,1,0,0,0],[0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0],[0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0],[0,0,1,0,1,0,0,1,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0],[1,1,0,1,1,0,1,0,0,1,1,0,0,0,1,0,1,0,0,0,0,1,1,0,0,1,0,0,0,0,0,0],[1,0,0,1,0,1,0,0,0,1,0,1,0,0,1,0,0,1,0,0,0,1,1,1,0,1,0,1,1,1,1,1],[0,1,0,0,0,1,1,1,0,1,1,0,1,1,1,0,0,0,1,0,1,0,1,1,1,1,0,0,0,0,1,1],[1,0,0,0,1,1,1,0,1,0,1,0,0,0,1,1,1,0,0,0,0,1,0,0,1,1,0,1,1,1,0,1],[0,1,1,1,1,0,0,1,1,1,0,0,0,1,1,0,1,1,1,0,0,1,0,0,1,0,0,1,1,1,1,1],[0,0,1,0,1,1,1,0,0,1,0,1,0,0,0,1,1,1,0,0,0,0,1,1,0,1,1,1,0,0,1,1],[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]]}`

	_, resLen := Prove([]byte(params))
	assert.True(resLen > 0)

	/*buf := unsafe.Slice((*byte)(res), resLen)

	fmt.Println(string(buf))
	var proveResult *OutputParams
	err = json.Unmarshal(buf, &proveResult)
	assert.NoError(err)

	verifyParams := &verifier.InputVerifyParams{
		Cipher: "chacha20",
		Proof:  proveResult.Proof,
		Input:  params.Input,
		Output: proveResult.Output,
	}

	bverifyParams, err := json.Marshal(verifyParams)
	assert.NoError(err)
	fmt.Println(string(bverifyParams))
	assert.True(verifier.Verify(bverifyParams))*/
}

/*func TestProveVerifyAES128(t *testing.T) {
	assert := test.NewAssert(t)

	InitFunc()
	bKey := make([]byte, 16)
	bNonce := make([]byte, 12)
	bPt := make([]byte, 64)

	rand.Read(bKey)
	rand.Read(bNonce)
	// rand.Read(bPt)
	bCt := make([]byte, len(bPt))

	block, err := aes.NewCipher(bKey)
	if err != nil {
		panic(err)
	}
	cipher := cipher.NewCTR(block, append(bNonce, binary.BigEndian.AppendUint32(nil, uint32(1))...))
	cipher.XORKeyStream(bCt, bPt)

	params := &InputParams{
		Cipher:  "aes-128-ctr",
		Key:     hex.EncodeToString(bKey),
		Nonce:   hex.EncodeToString(bNonce),
		Counter: 1,
		Input:   hex.EncodeToString(bPt),
	}

	bParams, err := json.Marshal(&params)
	assert.NoError(err)
	fmt.Println(string(bParams))
	res, resLen := Prove(bParams)
	assert.True(resLen > 0)

	buf := unsafe.Slice((*byte)(res), resLen)

	fmt.Println(string(buf))
	var proveResult *OutputParams
	err = json.Unmarshal(buf, &proveResult)
	assert.NoError(err)

	verifyParams := &verifier.InputVerifyParams{
		Cipher: "aes-128-ctr",
		Proof:  proveResult.Proof,
		Input:  params.Input,
		Output: proveResult.Output,
	}

	bverifyParams, err := json.Marshal(verifyParams)
	assert.NoError(err)
	fmt.Println(string(bverifyParams))
	assert.True(verifier.Verify(bverifyParams))
}

func TestProveVerifyAES256(t *testing.T) {
	assert := test.NewAssert(t)

	InitFunc()
	bKey := make([]byte, 32)
	bNonce := make([]byte, 12)
	bPt := make([]byte, 64)

	rand.Read(bKey)
	rand.Read(bNonce)
	// rand.Read(bPt)
	bCt := make([]byte, len(bPt))

	block, err := aes.NewCipher(bKey)
	if err != nil {
		panic(err)
	}
	cipher := cipher.NewCTR(block, append(bNonce, binary.BigEndian.AppendUint32(nil, uint32(1))...))
	cipher.XORKeyStream(bCt, bPt)

	params := &InputParams{
		Cipher:  "aes-256-ctr",
		Key:     hex.EncodeToString(bKey),
		Nonce:   hex.EncodeToString(bNonce),
		Counter: 1,
		Input:   hex.EncodeToString(bPt),
	}

	bParams, err := json.Marshal(&params)
	assert.NoError(err)
	fmt.Println(string(bParams))
	res, resLen := Prove(bParams)
	assert.True(resLen > 0)

	buf := unsafe.Slice((*byte)(res), resLen)

	fmt.Println(string(buf))
	var proveResult *OutputParams
	err = json.Unmarshal(buf, &proveResult)
	assert.NoError(err)

	verifyParams := &verifier.InputVerifyParams{
		Cipher: "aes-256-ctr",
		Proof:  proveResult.Proof,
		Input:  params.Input,
		Output: proveResult.Output,
	}

	bverifyParams, err := json.Marshal(verifyParams)
	assert.NoError(err)
	fmt.Println(string(bverifyParams))
	assert.True(verifier.Verify(bverifyParams))
}*/
