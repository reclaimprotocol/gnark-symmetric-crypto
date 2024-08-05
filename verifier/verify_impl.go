package verifier

import (
    "C"
    "bytes"
    "encoding/hex"
    "encoding/json"
    "fmt"
    "io/ioutil"
    "net/http"
    "sync"
    "time"

    "github.com/consensys/gnark-crypto/ecc"
    "github.com/consensys/gnark/backend/groth16"
    "github.com/rs/zerolog"
    "github.com/rs/zerolog/log"
)

type InputVerifyParams struct {
    Cipher        string  `json:"cipher"`
    Proof         string  `json:"proof"`
    PublicSignals []uint8 `json:"publicSignals"`
}

type VerifierParams struct {
    Verifier
    Init   func()
    isInit bool
}

var verifiers = make(map[string]*VerifierParams)

const (
    serverURL = "http://75.119.151.136:8080/keys" // Need to replace with actual public IP
)

func fetchKey(keyName string) ([]byte, error) {
    client := &http.Client{Timeout: 10 * time.Second}
    resp, err := client.Get(fmt.Sprintf("%s/%s", serverURL, keyName))
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
    }

    return ioutil.ReadAll(resp.Body)
}

var InitChachaFunc = sync.OnceFunc(func() {
    fmt.Println("loading ChaCha20 verifying key")
    vk := groth16.NewVerifyingKey(ecc.BN254)
    vkData, err := fetchKey("vk.bits")
    if err != nil {
        fmt.Println("failed to fetch key")
        panic(err)
    }
    _, err = vk.ReadFrom(bytes.NewBuffer(vkData))
    if err != nil {
        panic(err)
    }
    verifiers["chacha20"].Verifier = &ChachaVerifier{vk: vk}
    verifiers["chacha20"].isInit = true
})

var InitAES128Func = sync.OnceFunc(func() {
    fmt.Println("loading AES128 verifying key")
    vk := groth16.NewVerifyingKey(ecc.BN254)
    vkData, err := fetchKey("vk.aes128")
    if err != nil {
        fmt.Println("failed to fetch key")
        panic(err)
    }
    _, err = vk.ReadFrom(bytes.NewBuffer(vkData))
    if err != nil {
        panic(err)
    }
    verifiers["aes-128-ctr"].Verifier = &AESVerifier{vk: vk}
    verifiers["aes-128-ctr"].isInit = true
})

var InitAES256Func = sync.OnceFunc(func() {
    fmt.Println("loading AES256 verifying key")
    vk := groth16.NewVerifyingKey(ecc.BN254)
    vkData, err := fetchKey("vk.aes256")
    if err != nil {
        fmt.Println("failed to fetch key")
        panic(err)
    }
    _, err = vk.ReadFrom(bytes.NewBuffer(vkData))
    if err != nil {
        panic(err)
    }
    verifiers["aes-256-ctr"].Verifier = &AESVerifier{vk: vk}
    verifiers["aes-256-ctr"].isInit = true
})

func init() {
    zerolog.SetGlobalLevel(zerolog.Disabled)
    verifiers["chacha20"] = &VerifierParams{Init: InitChachaFunc}
    verifiers["aes-128-ctr"] = &VerifierParams{Init: InitAES128Func}
    verifiers["aes-256-ctr"] = &VerifierParams{Init: InitAES256Func}
}

var InitFunc = sync.OnceFunc(func() {
    var wg sync.WaitGroup
    wg.Add(3)
    go func() { InitChachaFunc(); wg.Done() }()
    go func() { InitAES128Func(); wg.Done() }()
    go func() { InitAES256Func(); wg.Done() }()
    wg.Wait()
})

func Verify(params []byte) (res bool) {
    defer func() {
        if err := recover(); err != nil {
            fmt.Println(err)
            res = false
        }
    }()

    var inputParams *InputVerifyParams
    err := json.Unmarshal(params, &inputParams)
    if err != nil {
        log.Err(err)
        return false
    }

    if verifierParams, ok := verifiers[inputParams.Cipher]; ok {
        if !verifierParams.isInit {
            verifierParams.Init()
        }
        return verifierParams.Verifier.Verify(mustHex(inputParams.Proof), inputParams.PublicSignals)
    }
    return false
}

func mustHex(s string) []byte {
    res, err := hex.DecodeString(s)
    if err != nil {
        panic(err)
    }
    return res
}
