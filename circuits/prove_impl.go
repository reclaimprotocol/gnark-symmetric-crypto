package circuits

import (
  "bytes"
  _ "embed"
  "encoding/hex"
  "encoding/json"
  "fmt"
  "sync"
  "unsafe"
  "time"
  "net/http"
  "io/ioutil"

  "github.com/consensys/gnark-crypto/ecc"
  "github.com/consensys/gnark/backend/groth16"
  "github.com/rs/zerolog"
)

// #include <stdlib.h>
import (
  "C"
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
  wg   *sync.WaitGroup
  Init func()
  isInit bool
}

var initChaCha sync.WaitGroup
var initAES128 sync.WaitGroup
var initAES256 sync.WaitGroup

var a, b, c bool


var InitChaChaFunc = sync.OnceFunc(func() {
    fmt.Println("loading ChaCha20")
    defer initChaCha.Done()

    pkChaCha := groth16.NewProvingKey(ecc.BN254)
    pkData, err := fetchKey("pk.bits")
    if err != nil {
        fmt.Println("failed to fetch key")
        panic(err)
    }
    _, err = pkChaCha.ReadFrom(bytes.NewBuffer(pkData))
    if err != nil {
        panic(err)
    }
    provers["chacha20"].Prover = &ChaChaProver{
        r1cs: GetR1CS("chacha20"),
        pk:   pkChaCha,
    }

    provers["chacha20"].isInit = true
    a = true
})

var InitAES128Func = sync.OnceFunc(func() {
    fmt.Println("loading AES128")
    defer initAES128.Done()

    pkAES128 := groth16.NewProvingKey(ecc.BN254)
    pkData, err := fetchKey("pk.aes128")
    if err != nil {
        fmt.Println("failed to fetch key")
        panic(err)
    }
    _, err = pkAES128.ReadFrom(bytes.NewBuffer(pkData))
    if err != nil {
        panic(err)
    }

    provers["aes-128-ctr"].Prover = &AESProver{
        r1cs: GetR1CS("aes-128-ctr"),
        pk:   pkAES128,
    }
    provers["aes-128-ctr"].isInit = true
    b = true
})


var InitAES256Func = sync.OnceFunc(func() {
    fmt.Println("loading AES256")
    defer initAES256.Done()

    pkAES256 := groth16.NewProvingKey(ecc.BN254)
    pkData, err := fetchKey("pk.aes256")
    if err != nil {
        fmt.Println("failed to fetch key")
        panic(err)
    }
    _, err = pkAES256.ReadFrom(bytes.NewBuffer(pkData))
    if err != nil {
        panic(err)
    }

    provers["aes-256-ctr"].Prover = &AESProver{
        r1cs: GetR1CS("aes-256-ctr"),
        pk:   pkAES256,
    }
    provers["aes-256-ctr"].isInit = true
    c = true
})

var provers = map[string]*ProverParams{
  "chacha20":    {wg: &initChaCha},
  "aes-128-ctr": {wg: &initAES128},
  "aes-256-ctr": {wg: &initAES256},
}

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
  wg.Add(3)
  go func() { InitChaChaFunc(); wg.Done() }()
  go func() { InitAES128Func(); wg.Done() }()
  go func() { InitAES256Func(); wg.Done() }()
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
