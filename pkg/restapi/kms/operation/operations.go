/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/trustbloc/edge-core/pkg/storage"

	support "github.com/trustbloc/hub-kms/pkg/internal/common"
	"github.com/trustbloc/hub-kms/pkg/keystore"
	kmsservice "github.com/trustbloc/hub-kms/pkg/kms"
)

const (
	kmsBasePath       = "/kms"
	keystoresEndpoint = kmsBasePath + "/keystores"
	keystoreEndpoint  = keystoresEndpoint + "/{keystoreID}"
	keysEndpoint      = keystoreEndpoint + "/keys"
	keyEndpoint       = keysEndpoint + "/{keyID}"

	readRequestFailure            = "Failed to read the request body: %s"
	createKeystoreFailure         = "Failed to create a keystore: %s"
	createKeystoreProviderFailure = "Failed to create a keystore provider: %s"
	createKeyFailure              = "Failed to create a key: %s"
	receivedBadRequest            = "Received bad request: %s"
)

// Operation defines handlers logic for Key Server.
type Operation struct {
	handlers []Handler
	provider Provider
}

// Handler defines an HTTP handler for the API endpoint.
type Handler interface {
	Path() string
	Method() string
	Handle() http.HandlerFunc
}

// Provider contains dependencies for Operation.
type Provider interface {
	StorageProvider() storage.Provider
	KMSCreator() KMSCreator
	Crypto() crypto.Crypto
}

// KMSCreatorContext provides a context to the KMSCreator method.
type KMSCreatorContext struct {
	KeystoreID string
	Passphrase string
}

// KMSCreator provides a method for creating a new key manager for the KMS service.
type KMSCreator func(ctx KMSCreatorContext) (kms.KeyManager, error)

// New returns a new Operation instance.
func New(provider Provider) *Operation {
	op := &Operation{provider: provider}
	op.registerHandlers()

	return op
}

// GetRESTHandlers gets all API handlers available for the Key Server service.
func (o *Operation) GetRESTHandlers() []Handler {
	return o.handlers
}

func (o *Operation) registerHandlers() {
	o.handlers = []Handler{
		support.NewHTTPHandler(keystoresEndpoint, http.MethodPost, o.createKeystoreHandler),
		support.NewHTTPHandler(keysEndpoint, http.MethodPost, o.createKeyHandler),
	}
}

func (o *Operation) createKeystoreHandler(rw http.ResponseWriter, req *http.Request) {
	requestBody, err := ioutil.ReadAll(req.Body)
	if err != nil {
		writeErrorResponse(rw, http.StatusInternalServerError, fmt.Sprintf(readRequestFailure, err))
		return
	}

	var request createKeystoreReq
	err = json.Unmarshal(requestBody, &request)
	if err != nil {
		writeErrorResponse(rw, http.StatusBadRequest, fmt.Sprintf(receivedBadRequest, err))
		return
	}

	keystoreID, err := createKeystore(request, o.provider.StorageProvider())
	if err != nil {
		writeErrorResponse(rw, http.StatusInternalServerError, fmt.Sprintf(createKeystoreFailure, err))
		return
	}

	rw.Header().Set("Location", keystoreLocation(req.Host, keystoreID))
	rw.WriteHeader(http.StatusCreated)
}

func createKeystore(req createKeystoreReq, storage storage.Provider) (string, error) {
	repo, err := keystore.NewRepository(storage)
	if err != nil {
		return "", err
	}

	// TODO: Pass keystore.Service as a dependency (https://github.com/trustbloc/hub-kms/issues/29)
	srv := keystore.NewService(repo)

	keystoreID, err := srv.Create(req.Controller)
	if err != nil {
		return "", err
	}

	return keystoreID, nil
}

type kmsProvider struct {
	keystore keystore.Repository
	kms      kms.KeyManager
	crypto   crypto.Crypto
}

func (k kmsProvider) Keystore() keystore.Repository {
	return k.keystore
}

func (k kmsProvider) KMS() kms.KeyManager {
	return k.kms
}

func (k kmsProvider) Crypto() crypto.Crypto {
	return k.crypto
}

func (o *Operation) createKeyHandler(rw http.ResponseWriter, req *http.Request) {
	requestBody, err := ioutil.ReadAll(req.Body)
	if err != nil {
		writeErrorResponse(rw, http.StatusInternalServerError, fmt.Sprintf(readRequestFailure, err))
		return
	}

	var request createKeyReq
	err = json.Unmarshal(requestBody, &request)
	if err != nil {
		writeErrorResponse(rw, http.StatusBadRequest, fmt.Sprintf(receivedBadRequest, err))
		return
	}

	ctx := KMSCreatorContext{
		KeystoreID: request.KeystoreID,
		Passphrase: request.Passphrase,
	}

	provider, err := prepareKMSProvider(o.provider, ctx)
	if err != nil {
		writeErrorResponse(rw, http.StatusInternalServerError, fmt.Sprintf(createKeystoreProviderFailure, err))
		return
	}

	keyID, err := createKey(request, provider)
	if err != nil {
		writeErrorResponse(rw, http.StatusInternalServerError, fmt.Sprintf(createKeyFailure, err))
		return
	}

	rw.Header().Set("Location", keyLocation(req.Host, request.KeystoreID, keyID))
	rw.WriteHeader(http.StatusCreated)
}

func prepareKMSProvider(provider Provider, ctx KMSCreatorContext) (*kmsProvider, error) {
	keystoreRepo, err := keystore.NewRepository(provider.StorageProvider())
	if err != nil {
		return nil, err
	}

	keyManager, err := provider.KMSCreator()(ctx)
	if err != nil {
		return nil, err
	}

	return &kmsProvider{
		keystore: keystoreRepo,
		kms:      keyManager,
		crypto:   provider.Crypto(),
	}, nil
}

func createKey(req createKeyReq, provider *kmsProvider) (string, error) {
	// TODO: Pass kms.Service as a dependency (https://github.com/trustbloc/hub-kms/issues/29)
	srv := kmsservice.NewService(provider)

	keyID, err := srv.CreateKey(req.KeystoreID, kms.KeyType(req.KeyType))
	if err != nil {
		return "", err
	}

	return keyID, nil
}

func writeErrorResponse(rw http.ResponseWriter, status int, msg string) {
	rw.WriteHeader(status)
	rw.Write([]byte(msg))
}

func keystoreLocation(hostURL, keystoreID string) string {
	// {hostURL}/kms/keystores/{keystoreID}
	return fmt.Sprintf("%s%s", hostURL,
		strings.ReplaceAll(keystoreEndpoint, "{keystoreID}", keystoreID))
}

func keyLocation(hostURL, keystoreID, keyID string) string {
	// {hostURL}/kms/keystores/{keystoreID}/keys/{keyID}
	r := strings.NewReplacer(
		"{keystoreID}", keystoreID,
		"{keyID}", keyID)

	return fmt.Sprintf("%s%s", hostURL, r.Replace(keyEndpoint))
}
