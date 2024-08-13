//go:build downloaded

package circuits

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
)

var circuits = map[string]string{
	"chacha20":    "r1cs.bits",
	"aes-128-ctr": "r1cs.aes128",
	"aes-256-ctr": "r1cs.aes256",
}

func fetchR1CS(keyName string) ([]byte, error) {
	client := &http.Client{Timeout: fetchTimeout}
	resp, err := client.Get(fmt.Sprintf("%s/%s", serverURL, keyName))
	if err != nil {
		return nil, fmt.Errorf("error fetching R1CS: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response body: %v", err)
	}

	return body, nil
}

func GetR1CS(cipher string) constraint.ConstraintSystem {
	fmt.Printf("Fetching R1CS for %s\n", cipher)

	r1csData, err := fetchR1CS(circuits[cipher])
	if err != nil {
		panic(fmt.Errorf("failed to fetch R1CS for %s: %v", cipher, err))
	}

	r1cs := groth16.NewCS(ecc.BN254)
	_, err = r1cs.ReadFrom(bytes.NewBuffer(r1csData))
	if err != nil {
		panic(err)
	}
	return r1cs
}
