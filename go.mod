module gnark-symmetric-crypto

go 1.22.0

toolchain go1.23.2

require (
	github.com/consensys/gnark v0.11.0
	github.com/consensys/gnark-crypto v0.14.0
	github.com/rs/zerolog v1.33.0 // indirect
	golang.org/x/crypto v0.28.0
)

require github.com/stretchr/testify v1.9.0

require (
	github.com/bits-and-blooms/bitset v1.14.3 // indirect
	github.com/blang/semver/v4 v4.0.0 // indirect
	github.com/consensys/bavard v0.1.22 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/fxamacker/cbor/v2 v2.7.0 // indirect
	github.com/google/pprof v0.0.0-20241023014458-598669927662 // indirect
	github.com/ingonyama-zk/icicle v1.1.0 // indirect
	github.com/ingonyama-zk/iciclegnark v0.1.1 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/mmcloughlin/addchain v0.4.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/ronanh/intcomp v1.1.0 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	golang.org/x/exp v0.0.0-20241009180824-f66d83c29e7c // indirect
	golang.org/x/sync v0.8.0 // indirect
	golang.org/x/sys v0.26.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	rsc.io/tmplfunc v0.0.3 // indirect
)

replace github.com/aws/aws-sdk-go-v2/service/kms => github.com/austinast/nitro-enclaves-sdk-go/kms v0.0.0-20240430100856-19343af9a0d0
