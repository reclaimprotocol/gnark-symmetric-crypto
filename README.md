<div>
    <div>
        <img src="https://raw.githubusercontent.com/reclaimprotocol/.github/main/assets/banners/Gnark.png"  />
    </div>
</div>

## Circuits
There are 3 circuits for Chacha ([v1](circuits/chacha), [v2](circuits/chachaV2), [v3](circuits/chachaV3))
2 circuits for AES ([v1](circuits/aes), [v2](circuits/aesV2))
V3 ChaCha20 and V2 AES are the most efficient implementations:

- ChaCha20 V3:
  - Operates on individual bits
  - Utilizes gadgets, which show improved performance in larger circuits
  - Optimized for better overall performance

- AES V2:
  - Employs lookup tables for transformations
  - Avoids on-the-fly calculations, resulting in faster execution
  - Significantly improves efficiency compared to the previous version

These optimized versions provide the best balance of speed and resource usage for their respective algorithms.

## Libraries
[Prover library](libraries/prover) runs on Client side Android, IOS and Linux for generating proofs
[Verifier library](libraries/verifier) runs on Server side Linux (X64 and ARM64) only for verifying proofs

## Compile all circuits, generate proving and verification keys
```
go run keygen.go
```

Proving keys & compiled circuits will be [here](circuits/generated)
Verification keys will be [here](libraries/verifier/impl/generated)


## Tests
```go
go test ./...
```

## Benchmarks
```go
cd libraries
go test -bench=.
```

# Build

Library files are located at
`libraries/prover/libprove.go`
`libraries/verifier/libverify.go`

## Android X86 and Arm64
install latest NDK:
set CC and CXX (use your paths)
```cgo
CC=android/ndk-bundle/toolchains/llvm/prebuilt/linux-x86_64/bin/x86_64-linux-android30-clang CXX=android/ndk-bundle/toolchains/llvm/prebuilt/linux-x86_64/bin/x86_64-linux-android30-clang++ CGO_ENABLED=1 GOOS=android GOARCH=amd64 go build -trimpath -ldflags="-s -w" -buildmode=c-shared -o libprove.so libraries/prover/libprove.go
CC=android/ndk-bundle/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android30-clang CXX=android/ndk-bundle/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android30-clang++ CGO_ENABLED=1 GOOS=android GOARCH=arm64 go build -trimpath -ldflags="-s -w" -buildmode=c-shared -o libprove.so libraries/prover/libprove.go
```

## Linux X64 (nodeJS)
```cgo
CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags '-s -w' -buildmode=c-shared -o libprove.so libraries/prover/libprove.go
CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags '-s -w' -buildmode=c-shared -o libverify.so libraries/verifier/libverify.go
```

## Linux Arm64 (for nodeJS on AWS)
```cgo
CC=aarch64-linux-gnu-gcc CGO_ENABLED=1 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="-s -w" -buildmode=c-shared -o libprove.so libraries/prover/libprove.go
CC=aarch64-linux-gnu-gcc CGO_ENABLED=1 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="-s -w" -buildmode=c-shared -o libverify.so libraries/verifier/libverify.go
```


