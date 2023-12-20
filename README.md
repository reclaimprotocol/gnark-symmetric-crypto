# gnark-chacha20
ChaCha20 implementation using gnark

# Run
```
go get ./...
go run .
go test ./...
```

# Build
## Wasm
```
GOOS=js GOARCH=wasm go build -o chacha.wasm
```

## Android X86 and Arm64
install latest NDK:
set CC and CXX (use your paths)
```
CC=/home/scratch/android/ndk-bundle/toolchains/llvm/prebuilt/linux-x86_64/bin/x86_64-linux-android30-clang CXX=/home/scratch/android/ndk-bundle/toolchains/llvm/prebuilt/linux-x86_64/bin/x86_64-linux-android30-clang++ CGO_ENABLED=1 GOOS=android GOARCH=amd64 go build -buildmode=c-shared -o libprove.so prove/bind.go
CC=/home/scratch/android/ndk-bundle/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android30-clang CXX=/home/scratch/android/ndk-bundle/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android30-clang++ CGO_ENABLED=1 GOOS=android GOARCH=arm64 go build -buildmode=c-shared -o libprove.so prove/bind.go
```



