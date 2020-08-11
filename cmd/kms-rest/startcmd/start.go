/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package startcmd

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/localkms"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock/local"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock/local/masterlock/hkdf"
	ariesstorage "github.com/hyperledger/aries-framework-go/pkg/storage"
	ariesmemstorage "github.com/hyperledger/aries-framework-go/pkg/storage/mem"
	"github.com/rs/cors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/trustbloc/edge-core/pkg/storage"
	"github.com/trustbloc/edge-core/pkg/storage/memstore"
	cmdutils "github.com/trustbloc/edge-core/pkg/utils/cmd"

	"github.com/trustbloc/hub-kms/pkg/restapi/healthcheck"
	kmsrest "github.com/trustbloc/hub-kms/pkg/restapi/kms"
	"github.com/trustbloc/hub-kms/pkg/restapi/kms/operation"
)

const (
	hostURLFlagName      = "host-url"
	hostURLFlagShorthand = "u"
	hostURLFlagUsage     = "URL to run the kms-rest instance on. Format: HostName:Port."
	hostURLEnvKey        = "KMS_REST_HOST_URL"

	tlsServeCertPathFlagName  = "tls-serve-cert"
	tlsServeCertPathFlagUsage = "Path to the server certificate to use when serving HTTPS." +
		" Alternatively, this can be set with the following environment variable: " + tlsServeCertPathEnvKey
	tlsServeCertPathEnvKey = "KMS_REST_TLS_SERVE_CERT"

	tlsServeKeyPathFlagName  = "tls-serve-key"
	tlsServeKeyPathFlagUsage = "Path to the private key to use when serving HTTPS." +
		" Alternatively, this can be set with the following environment variable: " + tlsServeKeyPathFlagEnvKey
	tlsServeKeyPathFlagEnvKey = "KMS_REST_TLS_SERVE_KEY"

	masterKeyURI       = "local-lock://%s"
	masterKeyStoreName = "masterkey"
	masterKeyDBKeyName = masterKeyStoreName

	keySize = sha256.Size
)

type server interface {
	ListenAndServeTLS(host, certFile, keyFile string, router http.Handler) error
}

// HTTPServer represents an actual HTTP server implementation.
type HTTPServer struct{}

// ListenAndServeTLS starts the server using the standard Go HTTPS implementation.
func (s *HTTPServer) ListenAndServeTLS(host, certFile, keyFile string, router http.Handler) error {
	return http.ListenAndServeTLS(host, certFile, keyFile, router)
}

// GetStartCmd returns the Cobra start command.
func GetStartCmd(srv server) *cobra.Command {
	startCmd := createStartCmd(srv)

	createFlags(startCmd)

	return startCmd
}

func createStartCmd(srv server) *cobra.Command {
	return &cobra.Command{
		Use:   "start",
		Short: "Start kms-rest",
		Long:  "Start kms-rest inside the hub-kms",
		RunE: func(cmd *cobra.Command, args []string) error {
			parameters, err := getKmsRestParameters(cmd)
			if err != nil {
				return err
			}

			return startKmsService(parameters, srv)
		},
	}
}

func createFlags(startCmd *cobra.Command) {
	startCmd.Flags().StringP(hostURLFlagName, hostURLFlagShorthand, "", hostURLFlagUsage)
	startCmd.Flags().StringP(tlsServeCertPathFlagName, "", "", tlsServeCertPathFlagUsage)
	startCmd.Flags().StringP(tlsServeKeyPathFlagName, "", "", tlsServeKeyPathFlagUsage)
}

type tlsParameters struct {
	serveCertPath string
	serveKeyPath  string
}

type kmsRestParameters struct {
	hostURL   string
	tlsParams *tlsParameters
}

func getKmsRestParameters(cmd *cobra.Command) (*kmsRestParameters, error) {
	hostURL, err := cmdutils.GetUserSetVarFromString(cmd, hostURLFlagName, hostURLEnvKey, false)
	if err != nil {
		return nil, err
	}

	tlsParams, err := getTLS(cmd)
	if err != nil {
		return nil, err
	}

	return &kmsRestParameters{
		hostURL:   hostURL,
		tlsParams: tlsParams,
	}, nil
}

func getTLS(cmd *cobra.Command) (*tlsParameters, error) {
	tlsServeCertPath, err := cmdutils.GetUserSetVarFromString(cmd, tlsServeCertPathFlagName,
		tlsServeCertPathEnvKey, true)
	if err != nil {
		return nil, err
	}

	tlsServeKeyPath, err := cmdutils.GetUserSetVarFromString(cmd, tlsServeKeyPathFlagName,
		tlsServeKeyPathFlagEnvKey, true)
	if err != nil {
		return nil, err
	}

	return &tlsParameters{
		serveCertPath: tlsServeCertPath,
		serveKeyPath:  tlsServeKeyPath,
	}, nil
}

func startKmsService(parameters *kmsRestParameters, srv server) error {
	router := mux.NewRouter()

	// add health check service API handlers
	healthCheckService := healthcheck.New()

	for _, handler := range healthCheckService.GetOperations() {
		router.HandleFunc(handler.Path(), handler.Handle()).Methods(handler.Method())
	}

	// add KMS service API handlers
	opProv, err := createOperationProvider()
	if err != nil {
		return nil
	}

	kmsService := kmsrest.New(opProv)

	for _, handler := range kmsService.GetOperations() {
		router.HandleFunc(handler.Path(), handler.Handle()).Methods(handler.Method())
	}

	log.Infof("starting KMS service on host %s", parameters.hostURL)

	return srv.ListenAndServeTLS(
		parameters.hostURL,
		parameters.tlsParams.serveCertPath,
		parameters.tlsParams.serveKeyPath,
		constructCORSHandler(router))
}

type operationProvider struct {
	storageProvider storage.Provider
	kmsCreator      operation.KMSCreator
	crypto          crypto.Crypto
}

func (k operationProvider) StorageProvider() storage.Provider {
	return k.storageProvider
}

func (k operationProvider) KMSCreator() operation.KMSCreator {
	return k.kmsCreator
}

func (k operationProvider) Crypto() crypto.Crypto {
	return k.crypto
}

func createOperationProvider() (operation.Provider, error) {
	c, err := tinkcrypto.New()
	if err != nil {
		return nil, err
	}

	// keystore storage is used for storing metadata about keystore and associated keys
	keystoreStorageProvider := memstore.NewProvider()

	// kms storage is used for storing keys in a secure manner
	kmsStorageProvider := ariesmemstorage.NewProvider()

	return operationProvider{
		storageProvider: keystoreStorageProvider,
		kmsCreator:      prepareKMSCreator(kmsStorageProvider),
		crypto:          c,
	}, nil
}

type kmsProvider struct {
	storageProvider ariesstorage.Provider
	secretLock      secretlock.Service
}

func (k kmsProvider) StorageProvider() ariesstorage.Provider {
	return k.storageProvider
}

func (k kmsProvider) SecretLock() secretlock.Service {
	return k.secretLock
}

func prepareKMSCreator(kmsStorageProvider ariesstorage.Provider) operation.KMSCreator {
	return func(ctx operation.KMSCreatorContext) (kms.KeyManager, error) {
		keyURI := fmt.Sprintf(masterKeyURI, ctx.KeystoreID)

		secretLock, err := prepareSecretLock(ctx.Passphrase)
		if err != nil {
			return nil, err
		}

		masterKeyReader, err := prepareMasterKeyReader(kmsStorageProvider, secretLock, keyURI)
		if err != nil {
			return nil, err
		}

		secretLockService, err := local.NewService(masterKeyReader, secretLock)
		if err != nil {
			return nil, err
		}

		kmsProv := kmsProvider{
			storageProvider: kmsStorageProvider,
			secretLock:      secretLockService,
		}

		localKMS, err := localkms.New(keyURI, kmsProv)
		if err != nil {
			return nil, err
		}

		return localKMS, nil
	}
}

func prepareSecretLock(passphrase string) (secretlock.Service, error) {
	return hkdf.NewMasterLock(passphrase, sha256.New, nil)
}

func prepareMasterKeyReader(kmsStorageProv ariesstorage.Provider, secLock secretlock.Service,
	keyURI string) (*bytes.Reader, error) {
	masterKeyStore, err := kmsStorageProv.OpenStore(masterKeyStoreName)
	if err != nil {
		return nil, err
	}

	masterKey, err := masterKeyStore.Get(masterKeyDBKeyName)
	if err != nil {
		if errors.Is(err, ariesstorage.ErrDataNotFound) {
			masterKey, err = prepareNewMasterKey(masterKeyStore, secLock, keyURI)
			if err != nil {
				return nil, err
			}
		} else {
			return nil, err
		}
	}

	return bytes.NewReader(masterKey), nil
}

func prepareNewMasterKey(masterKeyStore ariesstorage.Store, secLock secretlock.Service, keyURI string) ([]byte, error) {
	masterKeyContent := randomBytes(keySize)

	masterKeyEnc, err := secLock.Encrypt(keyURI, &secretlock.EncryptRequest{
		Plaintext: string(masterKeyContent),
	})

	if err != nil {
		return nil, err
	}

	masterKey := []byte(masterKeyEnc.Ciphertext)

	err = masterKeyStore.Put(masterKeyDBKeyName, masterKey)
	if err != nil {
		return nil, err
	}

	return masterKey, nil
}

func randomBytes(size uint32) []byte {
	buf := make([]byte, size)

	_, err := rand.Read(buf)
	if err != nil {
		panic(err) // out of randomness, should never happen :-)
	}

	return buf
}

func constructCORSHandler(handler http.Handler) http.Handler {
	return cors.New(
		cors.Options{
			AllowedMethods: []string{http.MethodGet, http.MethodPost},
			AllowedHeaders: []string{"Origin", "Accept", "Content-Type", "X-Requested-With", "Authorization"},
		},
	).Handler(handler)
}
