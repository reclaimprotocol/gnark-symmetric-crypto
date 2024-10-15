package main

import "C"
import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"gnark-symmetric-crypto/circuits/generated"
	"gnark-symmetric-crypto/libraries/prover/impl"
	"io"
	"net/http"
	"time"

	enclave "github.com/austinast/nitro-enclaves-sdk-go"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/mdlayher/vsock"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func prove(w http.ResponseWriter, req *http.Request) {

	defer func() {
		if err := recover(); err != nil {
			log.Err(nil).Any("error", err).Msg("prove")
			w.WriteHeader(http.StatusBadRequest)
			_, err = io.WriteString(w, fmt.Sprintf("{\"error\": \"%v\"}", err))
			if err != nil {
				log.Err(nil).Any("error", err).Msg("prove")
			}
			return
		}
	}()

	if req.Method != "POST" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_, err := io.WriteString(w, "POST only")
		if err != nil {
			log.Err(err).Msg("prove")
		}
		return
	}

	req.Body = http.MaxBytesReader(w, req.Body, 1<<20)

	proofReq, err := io.ReadAll(req.Body)
	if err != nil {
		log.Err(err).Msg("prove")
	}

	res := impl.Prove(proofReq)

	_, err = w.Write(res)
	if err != nil {
		log.Err(err).Msg("prove")
	}
}

func getRoot(w http.ResponseWriter, _ *http.Request) {
	_, err := io.WriteString(w, "Reclaim prover works\n")
	if err != nil {
		log.Err(err)
	}
}

func initProver() {
	assets := &generated.Assets
	pk, err := assets.ReadFile("pk.chacha20")
	if err != nil {
		log.Err(err).Msg("init")
	}
	r1cs, err := assets.ReadFile("r1cs.chacha20")
	if err != nil {
		log.Err(err).Msg("init")
	}
	if !(impl.InitAlgorithm(impl.CHACHA20, pk, r1cs)) {
		log.Err(errors.New("InitAlgorithm() for ChaCha20 failed")).Msg("init")
	}

	pk, err = assets.ReadFile("pk.aes128")
	if err != nil {
		log.Err(err).Msg("init")
	}
	r1cs, err = assets.ReadFile("r1cs.aes128")
	if err != nil {
		log.Err(err).Msg("init")
	}
	if !(impl.InitAlgorithm(impl.AES_128, pk, r1cs)) {
		log.Err(errors.New("InitAlgorithm() for AES-128 failed")).Msg("init")
	}

	pk, err = assets.ReadFile("pk.aes256")
	if err != nil {
		log.Err(err).Msg("init")
	}
	r1cs, err = assets.ReadFile("r1cs.aes256")
	if err != nil {
		log.Err(err).Msg("init")
	}
	if !(impl.InitAlgorithm(impl.AES_256, pk, r1cs)) {
		log.Err(errors.New("InitAlgorithm() for AES-256 failed")).Msg("init")
	}
}

func main() {
	zerolog.SetGlobalLevel(zerolog.DebugLevel)

	err := MakeKMSRequest()
	if err != nil {
		log.Err(err).Msg("make kms request")
	}

	initProver()
	mux := http.NewServeMux()
	mux.HandleFunc("/", getRoot)
	mux.HandleFunc("/prove", prove)

	ctx, cancelCtx := context.WithCancel(context.Background())
	server := &http.Server{
		Addr:              ":8888",
		Handler:           mux,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       120 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	l, err := vsock.Listen(8888, nil)
	if err != nil {
		log.Err(err).Msg("failed vsock.Listen")
		return
	}
	defer l.Close()

	go func() {
		log.Info().Msg("starting server")
		err = server.Serve(l)
		if errors.Is(err, http.ErrServerClosed) {
			fmt.Printf("server closed\n")
		} else if err != nil {
			fmt.Printf("error listening for server: %s\n", err)
		}
		cancelCtx()
	}()

	<-ctx.Done()
}

func MakeKMSRequest() error {
	enclaveHandle, err := enclave.GetOrInitializeHandle()
	if err != nil {
		return err
	}

	fmt.Println("Enclave handle received ok:", enclaveHandle)
	attestationDocument, err := enclaveHandle.Attest(enclave.AttestationOptions{})
	if err != nil {
		return err
	}

	fmt.Println("attestationDocument: ", hex.EncodeToString(attestationDocument))

	ctx := context.TODO()
	defaultConfig, err := config.LoadDefaultConfig(ctx, config.WithRegion("ap-south-1"))
	if err != nil {
		return err
	}

	fmt.Println("defaultConfig: ", defaultConfig)
	kmsClient := kms.NewFromConfig(defaultConfig)

	key, err := kmsClient.CreateKey(ctx, &kms.CreateKeyInput{
		Tags: []types.Tag{
			{
				TagKey:   aws.String("CreatedBy"),
				TagValue: aws.String("ReclaimProver"),
			},
		},
	})
	if err != nil {
		return err
	}
	fmt.Println("key created: ", key.KeyMetadata.KeyId)

	// Request a 32 byte data key from KMS, for use in AES-256 operations.
	dataKeyRes, err := kmsClient.GenerateDataKey(context.Background(), &kms.GenerateDataKeyInput{
		KeyId:   key.KeyMetadata.KeyId,
		KeySpec: types.DataKeySpecAes256,
		Recipient: &types.RecipientInfo{
			AttestationDocument:    attestationDocument,
			KeyEncryptionAlgorithm: types.KeyEncryptionMechanismRsaesOaepSha256,
		},
	})
	if err != nil {
		return err
	}
	fmt.Println("data Key received ok: ", dataKeyRes)
	return nil
}
