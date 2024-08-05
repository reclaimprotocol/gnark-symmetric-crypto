package verifier

import (
    "testing"
    "time"
)

func TestKeyLoading(t *testing.T) {
    InitFunc()  // This will trigger the loading of all keys
    time.Sleep(2 * time.Second)  // Wait for initializations to complete

    if !verifiers["chacha20"].isInit {
        t.Error("ChaCha20 verifier was not initialized")
    }
    if !verifiers["aes-128-ctr"].isInit {
        t.Error("AES-128 verifier was not initialized")
    }
    if !verifiers["aes-256-ctr"].isInit {
        t.Error("AES-256 verifier was not initialized")
    }

    // Test if verifiers are properly set
    if verifiers["chacha20"].Verifier == nil {
        t.Error("ChaCha20 verifier is nil")
    }
    if verifiers["aes-128-ctr"].Verifier == nil {
        t.Error("AES-128 verifier is nil")
    }
    if verifiers["aes-256-ctr"].Verifier == nil {
        t.Error("AES-256 verifier is nil")
    }
}
