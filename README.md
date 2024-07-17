# gnark-chacha20
ChaCha20, AES-128-CTR AES-256-CTR implementations using gnark

# Run keygen 
## Compile all circuits, generate proving and verification keys
```
go run keygen.go
```

# Build
## Wasm (deprecated)
```
GOOS=js GOARCH=wasm go build -o chacha.wasm
```

## Android X86 and Arm64
install latest NDK:
set CC and CXX (use your paths)
```
CC=android/ndk-bundle/toolchains/llvm/prebuilt/linux-x86_64/bin/x86_64-linux-android30-clang CXX=android/ndk-bundle/toolchains/llvm/prebuilt/linux-x86_64/bin/x86_64-linux-android30-clang++ CGO_ENABLED=1 GOOS=android GOARCH=amd64 go build -buildmode=c-shared -o libprove.so libprove.go
CC=android/ndk-bundle/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android30-clang CXX=android/ndk-bundle/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android30-clang++ CGO_ENABLED=1 GOOS=android GOARCH=arm64 go build -buildmode=c-shared -o libprove.so libprove.go
```

## Linux Arm64 (for AWS)
```cgo
CC=aarch64-linux-gnu-gcc CGO_ENABLED=1 GOOS=linux GOARCH=arm64 go build  -ldflags="-s -w" -buildmode=c-shared -o libprove.so libprove.go
CC=aarch64-linux-gnu-gcc CGO_ENABLED=1 GOOS=linux GOARCH=arm64 go build  -ldflags="-s -w" -buildmode=c-shared -o libverify.so libverify.go
```


