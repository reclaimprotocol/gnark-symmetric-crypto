# gnark-zk
ChaCha20, AES-128-CTR AES-256-CTR implementations using [Gnark](https://github.com/Consensys/gnark)

## Circuits
There are 3 circuits for Chacha ([v1](circuits/chacha), [v2](circuits/chachaV2), [v3](circuits/chachaV3))
2 circuits for AES ([v1](circuits/aes), [v2](circuits/aesV2))
V3 Chacha and V2 AES are the fastest. 
Chacha V3 works with individual bits, gadgets seem to benefit on larger scale circuits
AES V2 uses lookup tables instead of calculating transformations on the fly

## Libraries
[Prover library](libraries/prover) runs on Android, IOS and Linux
[Verifier library](libraries/verifier) runs on Linux (X64 and ARM64) only

## Usage
An example dart wrapper can be found [here](flutter_wrapper/libprove.dart)

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


