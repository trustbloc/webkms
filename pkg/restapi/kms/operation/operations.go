/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"strings"

	"github.com/gorilla/mux"
	arieskms "github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/trustbloc/edge-core/pkg/log"

	"github.com/trustbloc/hub-kms/pkg/internal/support"
	"github.com/trustbloc/hub-kms/pkg/keystore"
	"github.com/trustbloc/hub-kms/pkg/kms"
)

const (
	// HTTP params.
	keystoreIDQueryParam = "keystoreID"
	keyIDQueryParam      = "keyID"

	// API endpoints.
	kmsBasePath        = "/kms"
	keystoresEndpoint  = kmsBasePath + "/keystores"
	keystoreEndpoint   = keystoresEndpoint + "/{" + keystoreIDQueryParam + "}"
	keysEndpoint       = keystoreEndpoint + "/keys"
	keyEndpoint        = keysEndpoint + "/{" + keyIDQueryParam + "}"
	signEndpoint       = keyEndpoint + "/sign"
	verifyEndpoint     = keyEndpoint + "/verify"
	encryptEndpoint    = keyEndpoint + "/encrypt"
	decryptEndpoint    = keyEndpoint + "/decrypt"
	computeMACEndpoint = keyEndpoint + "/computemac"
	verifyMACEndpoint  = keyEndpoint + "/verifymac"

	// Error messages.
	receivedBadRequest      = "Received bad request: %s"
	createKeystoreFailure   = "Failed to create a keystore: %s"
	createKMSServiceFailure = "Failed to create a KMS service: %s"
	createKeyFailure        = "Failed to create a key: %s"
	signMessageFailure      = "Failed to sign a message: %s"
	verifyMessageFailure    = "Failed to verify a message: %s"
	encryptMessageFailure   = "Failed to encrypt a message: %s"
	decryptMessageFailure   = "Failed to decrypt a message: %s"
	computeMACFailure       = "Failed to compute MAC: %s"
	verifyMACFailure        = "Failed to verify MAC: %s"
)

// Handler defines an HTTP handler for the API endpoint.
type Handler interface {
	Path() string
	Method() string
	Handle() http.HandlerFunc
}

// Provider contains dependencies for Operation.
type Provider interface {
	KeystoreService() keystore.Service
	KMSServiceCreator() func(req *http.Request) (kms.Service, error)
	Logger() log.Logger
}

// Operation holds dependencies for handlers.
type Operation struct {
	keystoreService   keystore.Service
	kmsServiceCreator func(req *http.Request) (kms.Service, error)
	logger            log.Logger
}

// New returns a new Operation instance.
func New(provider Provider) *Operation {
	op := &Operation{
		keystoreService:   provider.KeystoreService(),
		kmsServiceCreator: provider.KMSServiceCreator(),
		logger:            provider.Logger(),
	}

	return op
}

// GetRESTHandlers gets handlers available for the hub-kms REST API.
func (o *Operation) GetRESTHandlers() []Handler {
	return []Handler{
		support.NewHTTPHandler(keystoresEndpoint, http.MethodPost, o.createKeystoreHandler),
		support.NewHTTPHandler(keysEndpoint, http.MethodPost, o.createKeyHandler),
		support.NewHTTPHandler(signEndpoint, http.MethodPost, o.signHandler),
		support.NewHTTPHandler(verifyEndpoint, http.MethodPost, o.verifyHandler),
		support.NewHTTPHandler(encryptEndpoint, http.MethodPost, o.encryptHandler),
		support.NewHTTPHandler(decryptEndpoint, http.MethodPost, o.decryptHandler),
		support.NewHTTPHandler(computeMACEndpoint, http.MethodPost, o.computeMACHandler),
		support.NewHTTPHandler(verifyMACEndpoint, http.MethodPost, o.verifyMACHandler),
	}
}

func (o *Operation) createKeystoreHandler(rw http.ResponseWriter, req *http.Request) {
	var request createKeystoreReq
	if ok := o.parseRequest(&request, rw, req); !ok {
		return
	}

	keystoreID, err := o.keystoreService.Create(request.Controller)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusInternalServerError, createKeystoreFailure, err)

		return
	}

	rw.Header().Set("Location", keystoreLocation(req.Host, keystoreID))
	rw.WriteHeader(http.StatusCreated)
}

func (o *Operation) createKeyHandler(rw http.ResponseWriter, req *http.Request) {
	kmsService, err := o.kmsServiceCreator(req)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusInternalServerError, createKMSServiceFailure, err)

		return
	}

	var request createKeyReq
	if ok := o.parseRequest(&request, rw, req); !ok {
		return
	}

	keystoreID := mux.Vars(req)[keystoreIDQueryParam]

	keyID, err := kmsService.CreateKey(keystoreID, arieskms.KeyType(request.KeyType))
	if err != nil {
		o.writeErrorResponse(rw, http.StatusInternalServerError, createKeyFailure, err)

		return
	}

	rw.Header().Set("Location", keyLocation(req.Host, keystoreID, keyID))
	rw.WriteHeader(http.StatusCreated)
}

//nolint:dupl // better readability
func (o *Operation) signHandler(rw http.ResponseWriter, req *http.Request) {
	kmsService, err := o.kmsServiceCreator(req)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusInternalServerError, createKMSServiceFailure, err)

		return
	}

	var request signReq
	if ok := o.parseRequest(&request, rw, req); !ok {
		return
	}

	keystoreID := mux.Vars(req)[keystoreIDQueryParam]
	keyID := mux.Vars(req)[keyIDQueryParam]

	signature, err := kmsService.Sign(keystoreID, keyID, []byte(request.Message))
	if err != nil {
		o.writeErrorResponse(rw, http.StatusInternalServerError, signMessageFailure, err)

		return
	}

	o.writeResponse(rw, signResp{
		Signature: base64.URLEncoding.EncodeToString(signature),
	})
}

//nolint:dupl // better readability
func (o *Operation) verifyHandler(rw http.ResponseWriter, req *http.Request) {
	kmsService, err := o.kmsServiceCreator(req)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusInternalServerError, createKMSServiceFailure, err)

		return
	}

	var request verifyReq
	if ok := o.parseRequest(&request, rw, req); !ok {
		return
	}

	keystoreID := mux.Vars(req)[keystoreIDQueryParam]
	keyID := mux.Vars(req)[keyIDQueryParam]

	signature, err := base64.URLEncoding.DecodeString(request.Signature)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusBadRequest, receivedBadRequest, err)

		return
	}

	err = kmsService.Verify(keystoreID, keyID, signature, []byte(request.Message))
	if err != nil {
		o.writeErrorResponse(rw, http.StatusInternalServerError, verifyMessageFailure, err)

		return
	}

	rw.WriteHeader(http.StatusOK)
}

func (o *Operation) encryptHandler(rw http.ResponseWriter, req *http.Request) {
	kmsService, err := o.kmsServiceCreator(req)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusInternalServerError, createKMSServiceFailure, err)

		return
	}

	var request encryptReq
	if ok := o.parseRequest(&request, rw, req); !ok {
		return
	}

	keystoreID := mux.Vars(req)[keystoreIDQueryParam]
	keyID := mux.Vars(req)[keyIDQueryParam]

	cipherText, nonce, err := kmsService.Encrypt(keystoreID, keyID, []byte(request.Message),
		[]byte(request.AdditionalData))
	if err != nil {
		o.writeErrorResponse(rw, http.StatusInternalServerError, encryptMessageFailure, err)

		return
	}

	o.writeResponse(rw, encryptResp{
		CipherText: base64.URLEncoding.EncodeToString(cipherText),
		Nonce:      base64.URLEncoding.EncodeToString(nonce),
	})
}

func (o *Operation) decryptHandler(rw http.ResponseWriter, req *http.Request) {
	kmsService, err := o.kmsServiceCreator(req)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusInternalServerError, createKMSServiceFailure, err)

		return
	}

	var request decryptReq
	if ok := o.parseRequest(&request, rw, req); !ok {
		return
	}

	keystoreID := mux.Vars(req)[keystoreIDQueryParam]
	keyID := mux.Vars(req)[keyIDQueryParam]

	cipherText, err := base64.URLEncoding.DecodeString(request.CipherText)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusBadRequest, receivedBadRequest, err)

		return
	}

	nonce, err := base64.URLEncoding.DecodeString(request.Nonce)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusBadRequest, receivedBadRequest, err)

		return
	}

	plainText, err := kmsService.Decrypt(keystoreID, keyID, cipherText, []byte(request.AdditionalData), nonce)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusInternalServerError, decryptMessageFailure, err)

		return
	}

	o.writeResponse(rw, decryptResp{
		PlainText: string(plainText),
	})
}

//nolint:dupl // better readability
func (o *Operation) computeMACHandler(rw http.ResponseWriter, req *http.Request) {
	kmsService, err := o.kmsServiceCreator(req)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusInternalServerError, createKMSServiceFailure, err)

		return
	}

	var request computeMACReq
	if ok := o.parseRequest(&request, rw, req); !ok {
		return
	}

	keystoreID := mux.Vars(req)[keystoreIDQueryParam]
	keyID := mux.Vars(req)[keyIDQueryParam]

	mac, err := kmsService.ComputeMAC(keystoreID, keyID, []byte(request.Data))
	if err != nil {
		o.writeErrorResponse(rw, http.StatusInternalServerError, computeMACFailure, err)

		return
	}

	o.writeResponse(rw, computeMACResp{
		MAC: base64.URLEncoding.EncodeToString(mac),
	})
}

//nolint:dupl // better readability
func (o *Operation) verifyMACHandler(rw http.ResponseWriter, req *http.Request) {
	kmsService, err := o.kmsServiceCreator(req)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusInternalServerError, createKMSServiceFailure, err)

		return
	}

	var request verifyMACReq
	if ok := o.parseRequest(&request, rw, req); !ok {
		return
	}

	keystoreID := mux.Vars(req)[keystoreIDQueryParam]
	keyID := mux.Vars(req)[keyIDQueryParam]

	mac, err := base64.URLEncoding.DecodeString(request.MAC)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusBadRequest, receivedBadRequest, err)

		return
	}

	err = kmsService.VerifyMAC(keystoreID, keyID, mac, []byte(request.Data))
	if err != nil {
		o.writeErrorResponse(rw, http.StatusInternalServerError, verifyMACFailure, err)

		return
	}

	rw.WriteHeader(http.StatusOK)
}

func (o *Operation) parseRequest(parsedReq interface{}, rw http.ResponseWriter, req *http.Request) bool {
	o.logger.Debugf(prepareDebugOutputForRequest(req, o.logger))

	if err := json.NewDecoder(req.Body).Decode(&parsedReq); err != nil {
		o.writeErrorResponse(rw, http.StatusBadRequest, receivedBadRequest, err)

		return false
	}

	return true
}

func prepareDebugOutputForRequest(req *http.Request, logger log.Logger) string {
	dump, err := httputil.DumpRequest(req, true)
	if err != nil {
		logger.Errorf("Failed to dump request: %s", err)
	}

	return string(dump)
}

type errorResponse struct {
	Message string `json:"errMessage,omitempty"`
}

func (o *Operation) writeErrorResponse(rw http.ResponseWriter, status int, messageFormat string, err error) {
	o.logger.Errorf(messageFormat, err)

	rw.WriteHeader(status)

	e := json.NewEncoder(rw).Encode(errorResponse{
		Message: fmt.Sprintf(messageFormat, kms.ErrorMessage(err)),
	})

	if e != nil {
		o.logger.Errorf("Unable to send an error message: %s", e)
	}
}

func (o *Operation) writeResponse(rw io.Writer, v interface{}) {
	err := json.NewEncoder(rw).Encode(v)
	if err != nil {
		o.logger.Errorf("Unable to send a response: %s", err)
	}
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
