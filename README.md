# gnark-zk
ChaCha20, AES-128-CTR AES-256-CTR implementations using Gnark

# Run keygen 
## Compile all circuits, generate proving and verification keys
```
go run keygen.go
```

# Build

Library files are located at
`libraries/prover/libprove.go`
`libraries/verifier/libverify.go`

## Build tags

To download circuits from CDN instead of compiling them add 
`-tags=download_circuits` after `go build`

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


