/*
Copyright © 2023 Jan Lauinger

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package aes

import (
	"encoding/hex"
	"testing"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

func TestAES256(t *testing.T) {

	assert := test.NewAssert(t)

	key := "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"
	plaintext := "f69f2445df4f9b17ad2b417be66c3710"
	ciphertext := "23304b7a39f9f3ff067d8d8f9e24ecc7"

	byteSlice, _ := hex.DecodeString(key)
	keyByteLen := len(byteSlice)
	byteSlice, _ = hex.DecodeString(plaintext)
	ptByteLen := len(byteSlice)
	byteSlice, _ = hex.DecodeString(ciphertext)
	ctByteLen := len(byteSlice)

	keyAssign := StrToIntSlice(key, true)
	ptAssign := StrToIntSlice(plaintext, true)
	ctAssign := StrToIntSlice(ciphertext, true)

	// witness values preparation
	assignment := AES256Wrapper{
		Key:        [32]frontend.Variable{},
		Plaintext:  [16]frontend.Variable{},
		Ciphertext: [16]frontend.Variable{},
	}

	// assign values here because required to use make in assignment
	for i := 0; i < keyByteLen; i++ {
		assignment.Key[i] = keyAssign[i]
	}
	for i := 0; i < ptByteLen; i++ {
		assignment.Plaintext[i] = ptAssign[i]
	}
	for i := 0; i < ctByteLen; i++ {
		assignment.Ciphertext[i] = ctAssign[i]
	}

	// var circuit SHA256
	var circuit AES256Wrapper

	assert.CheckCircuit(&circuit, test.WithValidAssignment(&assignment))
}
