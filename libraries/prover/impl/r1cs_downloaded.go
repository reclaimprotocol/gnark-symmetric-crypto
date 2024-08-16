package impl

import (
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"io"
	"net/http"
	"time"
)

var circuits = map[string]string{
	"chacha20":    "r1cs.bits",
	"aes-128-ctr": "r1cs.aes128",
	"aes-256-ctr": "r1cs.aes256",
}

var circuitHashes = map[string]string{
	"r1cs.bits":   "1ee90d87e5262923f0db0efe473a368a9c4bebdea0ddebe196e2d8363a538502",
	"r1cs.aes128": "b849a7b157921280e73f28716a097acc524b43ac133a98d8bb434c1072118f02",
	"r1cs.aes256": "9fc93c79c0656e95f1f6d573380edba22e07c9a97e2d876d86115cb04a5cf4cd",
}

const (
	serverURL    = "https://gnark-assets.s3.ap-south-1.amazonaws.com"
	fetchTimeout = 30 * time.Second
)

func FetchR1CS(keyName string) ([]byte, error) {
	client := &http.Client{Timeout: fetchTimeout}
	fmt.Printf("fetching R1CS %s\n", keyName)
	resp, err := client.Get(fmt.Sprintf("%s/%s", serverURL, keyName))
	if err != nil {
		return nil, fmt.Errorf("error fetching R1CS: %v", err)
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
	circuitHash := mustHex(circuitHashes[keyName])

	if subtle.ConstantTimeCompare(bodyHash[:], circuitHash) != 1 {
		return nil, fmt.Errorf("circuit hash mismatch")
	}

	return body, nil
}

/*func DownloadR1CS(cipher string) constraint.ConstraintSystem {
	fmt.Printf("Fetching R1CS for %s\n", cipher)

	r1csData, err := FetchR1CS(circuits[cipher])
	if err != nil {
		panic(fmt.Errorf("failed to fetch R1CS for %s: %v", cipher, err))
	}

	r1cs := groth16.NewCS(ecc.BN254)
	_, err = r1cs.ReadFrom(bytes.NewBuffer(r1csData))
	if err != nil {
		panic(err)
	}
	return r1cs
}*/
