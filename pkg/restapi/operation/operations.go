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

	"github.com/trustbloc/edge-core/pkg/storage"

	support "github.com/trustbloc/hub-kms/pkg/internal/common"
	"github.com/trustbloc/hub-kms/pkg/keystore"
)

const (
	kmsBasePath            = "/kms"
	keystoreEndpoint       = kmsBasePath + "/keystore"
	createKeystoreEndpoint = kmsBasePath + "/createKeystore"

	readRequestFailure           = "Failed to read the request body: %s"
	createKeystoreFailure        = "Failed to create a keystore: %s"
	receivedInvalidConfiguration = "Received invalid keystore configuration: %s"
)

// Operation defines handler logic for Key Server.
type Operation struct {
	keystore *keystore.Keystore
}

// Handler defines an HTTP handler for the API endpoint.
type Handler interface {
	Path() string
	Method() string
	Handle() http.HandlerFunc
}

// New returns a new Operation instance.
func New(provider storage.Provider) *Operation {
	return &Operation{
		keystore: keystore.New(provider),
	}
}

// GetRESTHandlers get all API handlers available for the KMS service.
func (o *Operation) GetRESTHandlers() []Handler {
	return []Handler{
		support.NewHTTPHandler(createKeystoreEndpoint, http.MethodPost, o.createKeystoreHandler),
	}
}

func (o *Operation) createKeystoreHandler(rw http.ResponseWriter, req *http.Request) {
	requestBody, err := ioutil.ReadAll(req.Body)
	if err != nil {
		writeErrorResponse(rw, http.StatusInternalServerError, fmt.Sprintf(readRequestFailure, err))
		return
	}

	var config keystore.Config
	err = json.Unmarshal(requestBody, &config)
	if err != nil {
		writeErrorResponse(rw, http.StatusBadRequest, fmt.Sprintf(receivedInvalidConfiguration, err))
		return
	}

	keystoreID, err := o.keystore.Create(config)
	if createKeystoreFailed(err, rw) {
		return
	}

	location := fmt.Sprintf("%s/%s/%s", req.Host, keystoreEndpoint, url.PathEscape(keystoreID))
	rw.Header().Set("Location", location)
	rw.WriteHeader(http.StatusCreated)
}

func createKeystoreFailed(err error, rw http.ResponseWriter) bool {
	if isConfigurationError(err) {
		writeErrorResponse(rw, http.StatusBadRequest, fmt.Sprintf(receivedInvalidConfiguration, err))
		return true
	}

	if errors.Is(err, keystore.ErrDuplicateKeystore) {
		writeErrorResponse(rw, http.StatusConflict, fmt.Sprintf(createKeystoreFailure, err))
		return true
	}

	if err != nil {
		writeErrorResponse(rw, http.StatusInternalServerError, fmt.Sprintf(createKeystoreFailure, err))
		return true
	}

	return false
}

func isConfigurationError(err error) bool {
	return errors.Is(err, keystore.ErrMissingController) ||
		errors.Is(err, keystore.ErrInvalidStartingSequence)
}

func writeErrorResponse(rw http.ResponseWriter, status int, msg string) {
	rw.WriteHeader(status)
	rw.Write([]byte(msg))
}
