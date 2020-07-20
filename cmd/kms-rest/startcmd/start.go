/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package startcmd

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
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
	ariesstorage "github.com/hyperledger/aries-framework-go/pkg/storage"
	ariesmemstorage "github.com/hyperledger/aries-framework-go/pkg/storage/mem"
	"github.com/rs/cors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/trustbloc/edge-core/pkg/storage"
	"github.com/trustbloc/edge-core/pkg/storage/memstore"
	cmdutils "github.com/trustbloc/edge-core/pkg/utils/cmd"

	"github.com/trustbloc/hub-kms/pkg/provider"
	"github.com/trustbloc/hub-kms/pkg/restapi/healthcheck"
	kmsrest "github.com/trustbloc/hub-kms/pkg/restapi/kms"
)

const (
	hostURLFlagName      = "host-url"
	hostURLFlagShorthand = "u"
	hostURLFlagUsage     = "URL to run the kms-rest instance on. Format: HostName:Port."
	hostURLEnvKey        = "KMS_REST_HOST_URL"

	masterKeyURI       = "local-lock://%s"
	masterKeyStoreName = "masterkey"
	masterKeyDBKeyName = masterKeyStoreName

	keySize = sha256.Size
)

type server interface {
	ListenAndServe(host string, router http.Handler) error
}

// HTTPServer represents an actual HTTP server implementation.
type HTTPServer struct{}

// ListenAndServe starts the server using the standard Go HTTP server implementation.
func (s *HTTPServer) ListenAndServe(host string, router http.Handler) error {
	return http.ListenAndServe(host, router)
}

type kmsRestParameters struct {
	hostURL string
}

type keystoreProvider struct {
	storageProvider storage.Provider
	kmsCreator      provider.KMSCreator
	crypto          crypto.Crypto
}

func (k keystoreProvider) StorageProvider() storage.Provider {
	return k.storageProvider
}

func (k keystoreProvider) KMSCreator() provider.KMSCreator {
	return k.kmsCreator
}

func (k keystoreProvider) Crypto() crypto.Crypto {
	return k.crypto
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
}

func getKmsRestParameters(cmd *cobra.Command) (*kmsRestParameters, error) {
	hostURL, err := cmdutils.GetUserSetVarFromString(cmd, hostURLFlagName, hostURLEnvKey, false)
	if err != nil {
		return nil, err
	}

	return &kmsRestParameters{
		hostURL: hostURL,
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
	keystoreProv, err := createKeystoreProvider()
	if err != nil {
		return nil
	}

	kmsService := kmsrest.New(keystoreProv)

	for _, handler := range kmsService.GetOperations() {
		router.HandleFunc(handler.Path(), handler.Handle()).Methods(handler.Method())
	}

	log.Infof("starting KMS service on host %s", parameters.hostURL)

	return srv.ListenAndServe(parameters.hostURL, constructCORSHandler(router))
}

func createKeystoreProvider() (provider.Provider, error) {
	c, err := tinkcrypto.New()
	if err != nil {
		return nil, err
	}

	// keystore storage is used for storing metadata about keystore and associated keys
	keystoreStorageProvider := memstore.NewProvider()
	// kms storage is used for storing keys in a secure manner
	kmsStorageProvider := ariesmemstorage.NewProvider()

	return keystoreProvider{
		storageProvider: keystoreStorageProvider,
		kmsCreator:      prepareKMSCreator(kmsStorageProvider),
		crypto:          c,
	}, nil
}

func prepareKMSCreator(kmsStorageProvider ariesstorage.Provider) provider.KMSCreator {
	return func(keystoreID string) (kms.KeyManager, error) {
		masterKeyReader, err := prepareMasterKeyReader(kmsStorageProvider)
		if err != nil {
			return nil, err
		}

		// TODO: Implement support for masterkey lock (https://github.com/trustbloc/hub-kms/issues/17)
		secretLockService, err := local.NewService(masterKeyReader, nil)
		if err != nil {
			return nil, err
		}

		kmsProv := kmsProvider{
			storageProvider: kmsStorageProvider,
			secretLock:      secretLockService,
		}

		keyURI := fmt.Sprintf(masterKeyURI, keystoreID)

		localKMS, err := localkms.New(keyURI, kmsProv)
		if err != nil {
			return nil, err
		}

		return localKMS, nil
	}
}

func prepareMasterKeyReader(kmsStorageProv ariesstorage.Provider) (*bytes.Reader, error) {
	masterKeyStore, err := kmsStorageProv.OpenStore(masterKeyStoreName)
	if err != nil {
		return nil, err
	}

	masterKey, err := masterKeyStore.Get(masterKeyDBKeyName)
	if err != nil {
		if errors.Is(err, ariesstorage.ErrDataNotFound) {
			masterKeyContent := randomBytes(keySize)
			masterKey = []byte(base64.URLEncoding.EncodeToString(masterKeyContent))

			putErr := masterKeyStore.Put(masterKeyDBKeyName, masterKey)
			if putErr != nil {
				return nil, putErr
			}
		} else {
			return nil, err
		}
	}

	return bytes.NewReader(masterKey), nil
}

func randomBytes(keySize uint32) []byte {
	buf := make([]byte, keySize)

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
