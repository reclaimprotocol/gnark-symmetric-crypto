package oprf

import (
	"encoding/json"
	"gnark-symmetric-crypto/utils"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
)

type InputOPRFParams struct {
	ServerPrivate []byte `json:"serverPrivate"`
	MaskedData    []byte `json:"maskedData"`
}
type OutputOPRFParams struct {
	Response []byte `json:"response"`
	C        []byte `json:"c"`
	S        []byte `json:"s"`
}

func OPRF(params []byte) []byte {
	var inputParams *InputOPRFParams
	err := json.Unmarshal(params, &inputParams)
	if err != nil {
		panic(err)
	}

	maskedData := new(twistededwards.PointAffine)
	err = maskedData.Unmarshal(inputParams.MaskedData)
	if err != nil {
		panic(err)
	}
	resp, err := utils.OPRF(new(big.Int).SetBytes(inputParams.ServerPrivate), maskedData)
	if err != nil {
		panic(err)
	}

	res, err := json.Marshal(&OutputOPRFParams{
		Response: resp.Response.Marshal(),
		C:        resp.C.Bytes(),
		S:        resp.S.Bytes(),
	})
	if err != nil {
		panic(err)
	}
	return res
}
