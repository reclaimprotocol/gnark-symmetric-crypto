package main

import (
	"encoding/json"
	"gnark-symmetric-crypto/utils"
	"syscall/js"
)

type Share struct {
	Index      int
	PrivateKey []byte `json:"privateKey"`
	PublicKey  []byte `json:"publicKey"`
}

type OutputGenerateParams struct {
	PrivateKey []byte   `json:"privateKey"`
	PublicKey  []byte   `json:"publicKey"`
	Shares     []*Share `json:"shares"`
}

func Keygen(nodes, threshold int) string {
	if threshold >= nodes {
		panic("threshold must be smaller than nodes")
	}

	keyParams := utils.TOPRFGenerateSharedKey(int(nodes), int(threshold))
	shareParams := make([]*Share, nodes)
	for i, share := range keyParams.Shares {
		shareParams[i] = &Share{
			Index:      i,
			PrivateKey: share.PrivateKey.Bytes(),
			PublicKey:  share.PublicKey.Marshal(),
		}
	}
	res := &OutputGenerateParams{
		PrivateKey: keyParams.PrivateKey.Bytes(),
		PublicKey:  keyParams.PublicKey.Marshal(),
		Shares:     shareParams,
	}

	bRes, err := json.Marshal(&res)
	if err != nil {
		panic(err)
	}

	return string(bRes)
}

func main() {

	js.Global().Set("Keygen", js.FuncOf(func(this js.Value, args []js.Value) any {
		return Keygen(args[0].Int(), args[1].Int())
	}))

	select {}
}
