/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"github.com/hyperledger/aries-framework-go/pkg/kms"

	support "github.com/trustbloc/hub-kms/pkg/internal/common"
	"github.com/trustbloc/hub-kms/pkg/keystore"
)

const (
	kmsBasePath       = "/kms"
	keystoresEndpoint = kmsBasePath + "/keystores"
	keystoreEndpoint  = keystoresEndpoint + "/{keystoreID}"
	keysEndpoint      = keystoreEndpoint + "/keys"
	keyEndpoint       = keysEndpoint + "/{keyID}"

	readRequestFailure           = "Failed to read the request body: %s"
	createKeystoreFailure        = "Failed to create a keystore: %s"
	createKeyFailure             = "Failed to create a key: %s"
	receivedInvalidConfiguration = "Received invalid keystore configuration: %s"
	receivedBadRequest           = "Received bad request: %s"
)

// Operation defines handlers logic for Key Server.
type Operation struct {
	handlers []Handler
	provider keystore.Provider
}

// Handler defines an HTTP handler for the API endpoint.
type Handler interface {
	Path() string
	Method() string
	Handle() http.HandlerFunc
}

// New returns a new Key Server Operation instance.
func New(provider keystore.Provider) *Operation {
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

	keystoreID, err := createKeystore(request, o.provider)

	if isConfigurationError(err) {
		writeErrorResponse(rw, http.StatusBadRequest, fmt.Sprintf(receivedInvalidConfiguration, err))
		return
	}

	if errors.Is(err, keystore.ErrDuplicateKeystore) {
		writeErrorResponse(rw, http.StatusConflict, fmt.Sprintf(createKeystoreFailure, err))
		return
	}

	if err != nil {
		writeErrorResponse(rw, http.StatusInternalServerError, fmt.Sprintf(createKeystoreFailure, err))
		return
	}

	rw.Header().Set("Location", keystoreLocation(req.Host, keystoreID))
	rw.WriteHeader(http.StatusCreated)
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

	keyID, err := createKey(request, o.provider)

	if errors.Is(err, keystore.ErrInvalidKeystore) {
		writeErrorResponse(rw, http.StatusBadRequest, fmt.Sprintf(createKeyFailure, err))
		return
	}

	if err != nil {
		writeErrorResponse(rw, http.StatusInternalServerError, fmt.Sprintf(createKeyFailure, err))
		return
	}

	rw.Header().Set("Location", keyLocation(req.Host, request.KeystoreID, keyID))
	rw.WriteHeader(http.StatusCreated)
}

func createKeystore(req createKeystoreReq, provider keystore.Provider) (string, error) {
	config := keystore.Configuration{
		Sequence:   req.Sequence,
		Controller: req.Controller,
	}

	return keystore.CreateKeystore(config, provider.StorageProvider())
}

func createKey(req createKeyReq, provider keystore.Provider) (string, error) {
	k, err := keystore.New(req.KeystoreID, provider)
	if err != nil {
		return "", err
	}

	keyID, err := k.CreateKey(kms.KeyType(req.KeyType))
	if err != nil {
		return "", err
	}

	return keyID, nil
}

func isConfigurationError(err error) bool {
	return errors.Is(err, keystore.ErrMissingController) ||
		errors.Is(err, keystore.ErrInvalidStartingSequence)
}

func writeErrorResponse(rw http.ResponseWriter, status int, msg string) {
	rw.WriteHeader(status)
	rw.Write([]byte(msg))
}

func keystoreLocation(hostURL, keystoreID string) string {
	// {hostURL}/kms/keystores/{keystoreID}
	return fmt.Sprintf("%s/%s/%s", hostURL, keystoreEndpoint, url.PathEscape(keystoreID))
}

func keyLocation(hostURL, keystoreID, keyID string) string {
	// {hostURL}/kms/keystores/{keystoreID}/keys/{keyID}
	r := strings.NewReplacer(
		"{keystoreID}", url.PathEscape(keystoreID),
		"{keyID}", url.PathEscape(keyID))

	return fmt.Sprintf("%s/%s", hostURL, r.Replace(keyEndpoint))
}
