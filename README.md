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

## Android
install ARM64 gcc:
```
apt install gcc-aarch64-linux-gnu
```
set CC
```
export CC=aarch64-linux-gnu-gcc
```
GOOS=linux GOARCH=arm64 go build -buildmode=c-shared -o prove.so prove/bind.go
```


