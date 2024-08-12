package circuits

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
	"unsafe"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/rs/zerolog"
)

// #include <stdlib.h>
import (
	"C"
)

const (
	serverURL    = "https://gnark-assets.s3.ap-south-1.amazonaws.com"
	fetchTimeout = 30 * time.Second
)

type InputParamsCipher struct {
	Cipher string `json:"cipher"`
}

type InputParamsChaCha struct {
	Cipher  string    `json:"cipher"`
	Key     [][]uint8 `json:"key"`
	Nonce   [][]uint8 `json:"nonce"`
	Counter []uint8   `json:"counter"`
	Input   [][]uint8 `json:"input"`
}

type InputParamsAES struct {
	Cipher  string  `json:"cipher"`
	Key     []uint8 `json:"key"`
	Nonce   []uint8 `json:"nonce"`
	Counter []uint8 `json:"counter"`
	Input   []uint8 `json:"input"`
}

type Proof struct {
	ProofJson string `json:"proofJson"`
}

type OutputParams struct {
	Proof         Proof `json:"proof"`
	PublicSignals []int `json:"publicSignals"`
}

type ProverParams struct {
	Prover
	wg     *sync.WaitGroup
	Init   func()
	isInit bool
}

var initChaCha sync.WaitGroup
var initAES128 sync.WaitGroup
var initAES256 sync.WaitGroup

const (
	ChaChaHash = "500d19eeccee0b3749e369c1839a1de0183dc7e8e43c4f9ad36e9c4b6537f03e"
	AES128Hash = "5c4053dc1a731b5dcd059ca9e1753b018f8713ff4838504a2232f2d4cf5e0526"
	AES256Hash = "0c0c06a3dbfe1f155a8b191b0d6ea081aae6e74cd77de3acc1d487094b3cab31"
)

var InitChaChaFunc = sync.OnceFunc(func() {
	fmt.Println("loading ChaCha20")
	defer initChaCha.Done()

	pkChaCha, err := fetchKey("pk.bits", ChaChaHash)
	if err != nil {
		fmt.Println("failed to fetch key")
		panic(err)
	}

	provers["chacha20"].Prover = &ChaChaProver{
		r1cs: GetR1CS("chacha20"),
		pk:   pkChaCha,
	}

	provers["chacha20"].isInit = true
})

var InitAES128Func = sync.OnceFunc(func() {
	fmt.Println("loading AES128")
	defer initAES128.Done()

	pkAES128, err := fetchKey("pk.aes128", AES128Hash)
	if err != nil {
		fmt.Println("failed to fetch key")
		panic(err)
	}

	provers["aes-128-ctr"].Prover = &AESProver{
		r1cs: GetR1CS("aes-128-ctr"),
		pk:   pkAES128,
	}
	provers["aes-128-ctr"].isInit = true
})

var InitAES256Func = sync.OnceFunc(func() {
	fmt.Println("loading AES256")
	defer initAES256.Done()

	pkAES256, err := fetchKey("pk.aes256", AES256Hash)
	if err != nil {
		fmt.Println("failed to fetch key")
		panic(err)
	}

	provers["aes-256-ctr"].Prover = &AESProver{
		r1cs: GetR1CS("aes-256-ctr"),
		pk:   pkAES256,
	}
	provers["aes-256-ctr"].isInit = true
})

var provers = map[string]*ProverParams{
	"chacha20":    {wg: &initChaCha},
	"aes-128-ctr": {wg: &initAES128},
	"aes-256-ctr": {wg: &initAES256},
}

func fetchKey(keyName string, keyHashStr string) (groth16.ProvingKey, error) {
	client := &http.Client{Timeout: fetchTimeout}
	keyUrl := fmt.Sprintf("%s/%s", serverURL, keyName)
	resp, err := client.Get(keyUrl)
	if err != nil {
		return nil, fmt.Errorf("error fetching key: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response body: %v", err)
	}

	bodyHash := sha256.Sum256(body)
	keyHash := mustHex(keyHashStr)

	if subtle.ConstantTimeCompare(bodyHash[:], keyHash) != 1 {
		return nil, fmt.Errorf("invalid key hash")
	}

	pkey := groth16.NewProvingKey(ecc.BN254)
	_, err = pkey.ReadFrom(bytes.NewBuffer(body))
	if err != nil {
		return nil, fmt.Errorf("error reading proving key: %v", err)
	}
	return pkey, nil
}

func initDone() bool {
	return provers["chacha20"].isInit && provers["aes-128-ctr"].isInit && provers["aes-256-ctr"].isInit
}

func init() {
	zerolog.SetGlobalLevel(zerolog.Disabled)
	initChaCha.Add(1)
	initAES128.Add(1)
	initAES256.Add(1)
	provers["chacha20"].Init = InitChaChaFunc
	provers["aes-128-ctr"].Init = InitAES128Func
	provers["aes-256-ctr"].Init = InitAES256Func
}

var InitFunc = sync.OnceFunc(func() {
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		// we want them loaded consecutively if over network
		InitChaChaFunc()
		InitAES128Func()
		InitAES256Func()
	}()
	wg.Wait()
})

func Prove(params []byte) (proofRes unsafe.Pointer, resLen int) {
	defer func() {
		if err := recover(); err != nil {
			fmt.Println(err)
			bRes, er := json.Marshal(err)
			if er != nil {
				fmt.Println(er)
			}
			proofRes, resLen = C.CBytes(bRes), len(bRes)
		}
	}()

	var cipherParams *InputParamsCipher
	err := json.Unmarshal(params, &cipherParams)
	if err != nil {
		panic(err)
	}
	if prover, ok := provers[cipherParams.Cipher]; ok {
		go prover.Init()
		prover.wg.Wait()

		if cipherParams.Cipher == "chacha20" {
			var inputParams *InputParamsChaCha
			err = json.Unmarshal(params, &inputParams)
			if err != nil {
				panic(err)
			}

			proof, ciphertext := prover.ProveChaCha(inputParams.Key, inputParams.Nonce, inputParams.Counter, inputParams.Input)

			ct := make([]int, 0, len(ciphertext))
			for i := 0; i < len(ciphertext); i++ {
				ct = append(ct, int(ciphertext[i]))
			}

			res, er := json.Marshal(&OutputParams{
				Proof: Proof{
					ProofJson: hex.EncodeToString(proof),
				},
				PublicSignals: ct,
			})
			if er != nil {
				panic(er)
			}
			return C.CBytes(res), len(res)
		} else {
			{
				var inputParams *InputParamsAES
				err = json.Unmarshal(params, &inputParams)
				if err != nil {
					panic(err)
				}

				proof, ciphertext := prover.ProveAES(inputParams.Key, inputParams.Nonce, inputParams.Counter, inputParams.Input)
				ct := make([]int, 0, len(ciphertext))
				for i := 0; i < len(ciphertext); i++ {
					ct = append(ct, int(ciphertext[i]))
				}
				res, er := json.Marshal(&OutputParams{
					Proof: Proof{
						ProofJson: hex.EncodeToString(proof),
					},
					PublicSignals: ct,
				})
				if er != nil {
					panic(er)
				}
				return C.CBytes(res), len(res)
			}
		}

	} else {
		panic("could not find prover " + cipherParams.Cipher)
	}
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}
