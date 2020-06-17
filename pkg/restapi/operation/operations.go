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
	"net/url"

	"github.com/google/uuid"

	support "github.com/trustbloc/hub-kms/pkg/internal/common"
	"github.com/trustbloc/hub-kms/pkg/keystore"
	"github.com/trustbloc/hub-kms/pkg/restapi/models"
)

const (
	kmsBasePath            = "/kms"
	keystoreEndpoint       = kmsBasePath + "/keystore"
	createKeystoreEndpoint = kmsBasePath + "/createKeystore"

	keystoreIDFormat = "urn:uuid:%s"

	readRequestFailure           = "Failed to read the request body: %s"
	createKeystoreFailure        = "Failed to create a keystore: %s"
	receivedInvalidConfiguration = "Received invalid keystore configuration: %s"
)

// Operation defines handler logic for the KMS service.
type Operation struct {
	keystore keystore.Provider
}

// Handler defines an HTTP handler for the API endpoint.
type Handler interface {
	Path() string
	Method() string
	Handle() http.HandlerFunc
}

// New returns a new Operation instance.
func New(keystore keystore.Provider) *Operation {
	return &Operation{
		keystore: keystore,
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

	var config models.KeystoreConfiguration
	err = json.Unmarshal(requestBody, &config)
	if err != nil {
		writeErrorResponse(rw, http.StatusBadRequest, fmt.Sprintf(receivedInvalidConfiguration, err))
		return
	}

	keystoreID, err := o.createKeystore()
	if err != nil {
		writeErrorResponse(rw, http.StatusInternalServerError, fmt.Sprintf(createKeystoreFailure, err))
		return
	}

	location := fmt.Sprintf("%s/%s/%s", req.Host, keystoreEndpoint, url.PathEscape(keystoreID))
	rw.Header().Set("Location", location)
	rw.WriteHeader(http.StatusCreated)
}

func (o *Operation) createKeystore() (string, error) {
	guid := uuid.New()
	keystoreID := fmt.Sprintf(keystoreIDFormat, guid)

	err := o.keystore.CreateStore(keystoreID)
	if err != nil {
		return "", err
	}

	return keystoreID, nil
}

func writeErrorResponse(rw http.ResponseWriter, status int, msg string) {
	rw.WriteHeader(status)
	rw.Write([]byte(msg))
}
