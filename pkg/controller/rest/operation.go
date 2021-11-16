/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package rest

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/hyperledger/aries-framework-go/pkg/common/log"

	"github.com/trustbloc/kms/pkg/controller/command"
	"github.com/trustbloc/kms/pkg/controller/errors"
)

// API endpoints.
const (
	keyStoreVarName = "keystore"
	keyVarName      = "key"
	BaseV1Path      = "/v1"
	KeyStorePath    = BaseV1Path + "/keystore"
	DIDPath         = KeyStorePath + "/did"
	KeyPath         = KeyStorePath + "/{" + keyStoreVarName + "}/key"
	ExportKeyPath   = KeyPath + "/{" + keyVarName + "}/export"
	SignPath        = KeyPath + "/{" + keyVarName + "}/sign"
	VerifyPath      = KeyPath + "/{" + keyVarName + "}/verify"
	EncryptPath     = KeyPath + "/{" + keyVarName + "}/encrypt"
	DecryptPath     = KeyPath + "/{" + keyVarName + "}/decrypt"
	ComputeMACPath  = KeyPath + "/{" + keyVarName + "}/computemac"
	VerifyMACPath   = KeyPath + "/{" + keyVarName + "}/verifymac"
	HealthCheckPath = "/healthcheck"
)

const (
	contentType     = "Content-Type"
	applicationJSON = "application/json"
)

var logger = log.New("controller/rest")

// Cmd defines command methods.
type Cmd interface {
	CreateDID(w io.Writer, r io.Reader) error
	CreateKeyStore(w io.Writer, r io.Reader) error
	CreateKey(w io.Writer, r io.Reader) error
	ExportKey(w io.Writer, r io.Reader) error
	ImportKey(w io.Writer, r io.Reader) error
	Sign(w io.Writer, r io.Reader) error
	Verify(w io.Writer, r io.Reader) error
	Encrypt(w io.Writer, r io.Reader) error
	Decrypt(w io.Writer, r io.Reader) error
	ComputeMAC(w io.Writer, r io.Reader) error
	VerifyMAC(w io.Writer, r io.Reader) error
}

// Operation represents REST API controller.
type Operation struct {
	cmd Cmd
}

// New returns REST API controller.
func New(cmd Cmd) *Operation {
	return &Operation{cmd: cmd}
}

// GetRESTHandlers returns list of all handlers supported by this controller.
func (o *Operation) GetRESTHandlers() []Handler {
	return []Handler{
		NewHTTPHandler(DIDPath, http.MethodPost, o.CreateDID),
		NewHTTPHandler(KeyStorePath, http.MethodPost, o.CreateKeyStore),
		NewHTTPHandler(KeyPath, http.MethodPost, o.CreateKey),
		NewHTTPHandler(KeyPath, http.MethodPut, o.ImportKey),
		NewHTTPHandler(ExportKeyPath, http.MethodGet, o.ExportKey),
		NewHTTPHandler(SignPath, http.MethodPost, o.Sign),
		NewHTTPHandler(VerifyPath, http.MethodPost, o.Verify),
		NewHTTPHandler(EncryptPath, http.MethodPost, o.Encrypt),
		NewHTTPHandler(DecryptPath, http.MethodPost, o.Decrypt),
		NewHTTPHandler(ComputeMACPath, http.MethodPost, o.ComputeMAC),
		NewHTTPHandler(VerifyMACPath, http.MethodPost, o.VerifyMAC),
		NewHTTPHandler(HealthCheckPath, http.MethodGet, o.HealthCheck),
	}
}

// CreateDID swagger:route POST /v1/keystore/did kms createDIDReq
//
// Creates a DID.
//
// Responses:
//        201: createDIDResp
//    default: errorResp
func (o *Operation) CreateDID(rw http.ResponseWriter, req *http.Request) {
	execute(o.cmd.CreateDID, rw, req)
}

// CreateKeyStore swagger:route POST /v1/keystore kms createKeyStoreReq
//
// Creates a new key store.
//
// Responses:
//        201: createKeyStoreResp
//    default: errorResp
func (o *Operation) CreateKeyStore(rw http.ResponseWriter, req *http.Request) {
	execute(o.cmd.CreateKeyStore, rw, req)
}

// CreateKey swagger:route POST /v1/keystore/{key_store_id}/key kms createKeyReq
//
// Creates a new key.
//
// Responses:
//        201: createKeyResp
//    default: errorResp
func (o *Operation) CreateKey(rw http.ResponseWriter, req *http.Request) {
	execute(o.cmd.CreateKey, rw, req)
}

// ImportKey swagger:route PUT /v1/keystore/{key_store_id}/key kms importKeyReq
//
// Imports a private key.
//
// Responses:
//        201: importKeyResp
//    default: errorResp
func (o *Operation) ImportKey(rw http.ResponseWriter, req *http.Request) {
	execute(o.cmd.ImportKey, rw, req)
}

// ExportKey swagger:route GET /v1/keystore/{key_store_id}/key/{key_id} kms exportKeyReq
//
// Exports a public key.
//
// Responses:
//        200: exportKeyResp
//    default: errorResp
func (o *Operation) ExportKey(rw http.ResponseWriter, req *http.Request) {
	execute(o.cmd.ExportKey, rw, req)
}

// Sign swagger:route POST /v1/keystore/{key_store_id}/key/{key_id}/sign crypto signReq
//
// Signs a message.
//
// Responses:
//        200: signResp
//    default: errorResp
func (o *Operation) Sign(rw http.ResponseWriter, req *http.Request) {
	execute(o.cmd.Sign, rw, req)
}

// Verify swagger:route POST /v1/keystore/{key_store_id}/key/{key_id}/verify crypto verifyReq
//
// Verifies a signature.
//
// Responses:
//        200: verifyResp
//    default: errorResp
func (o *Operation) Verify(rw http.ResponseWriter, req *http.Request) {
	execute(o.cmd.Verify, rw, req)
}

// Encrypt swagger:route POST /v1/keystore/{key_store_id}/key/{key_id}/encrypt crypto encryptReq
//
// Encrypts a message with associated authenticated data.
//
// Encryption with associated data ensures authenticity (who the sender is) and integrity (the data has not been
// tampered with) of that data, but not its secrecy.
//
// Responses:
//        200: encryptResp
//    default: errorResp
func (o *Operation) Encrypt(rw http.ResponseWriter, req *http.Request) {
	execute(o.cmd.Encrypt, rw, req)
}

// Decrypt swagger:route POST /v1/keystore/{key_store_id}/key/{key_id}/decrypt crypto decryptReq
//
// Decrypts a ciphertext with associated authenticated data.
//
// The decryption verifies the authenticity and integrity of the associated data, but there are no guarantees with
// regard to secrecy of that data.
//
// Responses:
//        200: decryptResp
//    default: errorResp
func (o *Operation) Decrypt(rw http.ResponseWriter, req *http.Request) {
	execute(o.cmd.Decrypt, rw, req)
}

// ComputeMAC swagger:route POST /v1/keystore/{key_store_id}/key/{key_id}/computemac crypto computeMACReq
//
// Computes message authentication code (MAC) for data.
//
// MAC provides symmetric message authentication. Computed authentication tag for given data allows the recipient
// to verify that data are from the expected sender and have not been modified.
//
// Responses:
//        200: computeMACResp
//    default: errorResp
func (o *Operation) ComputeMAC(rw http.ResponseWriter, req *http.Request) {
	execute(o.cmd.ComputeMAC, rw, req)
}

// VerifyMAC swagger:route POST /v1/keystore/{key_store_id}/key/{key_id}/verifymac crypto verifyMACReq
//
// Verifies whether MAC is a correct authentication code for data.
//
// Responses:
//        200: verifyMACResp
//    default: errorResp
func (o *Operation) VerifyMAC(rw http.ResponseWriter, req *http.Request) {
	execute(o.cmd.VerifyMAC, rw, req)
}

// HealthCheck swagger:route GET /healthcheck server healthCheckReq
//
// Returns a health check status.
//
// Responses:
//        200: healthCheckResp
//    default: errorResp
func (o *Operation) HealthCheck(rw http.ResponseWriter, _ *http.Request) {
	rw.Header().Set(contentType, applicationJSON)

	err := json.NewEncoder(rw).Encode(map[string]interface{}{ //nolint: wrapcheck
		"status":       "success",
		"current_time": time.Now(),
	})
	if err != nil {
		sendError(rw, fmt.Errorf("%w: encode health check response", errors.ErrInternal))
	}
}

func execute(exec command.Exec, rw http.ResponseWriter, req *http.Request) {
	rw.Header().Set(contentType, applicationJSON)

	r, err := wrapRequest(req)
	if err != nil {
		sendError(rw, fmt.Errorf("wrap request: %w", err))

		return
	}

	if err = exec(rw, bytes.NewBuffer(r)); err != nil {
		sendError(rw, err)
	}
}

func wrapRequest(req *http.Request) ([]byte, error) {
	var buf bytes.Buffer

	_, err := io.Copy(&buf, req.Body)
	if err != nil {
		return nil, fmt.Errorf("%w: copy request body", errors.ErrInternal)
	}

	var secret []byte

	secretHeader := req.Header.Get("Kms-Secret")

	if secretHeader != "" {
		secret, err = base64.StdEncoding.DecodeString(secretHeader)
		if err != nil {
			return nil, fmt.Errorf("%w: decode secret share from header", errors.ErrBadRequest)
		}
	}

	vars := mux.Vars(req)

	return json.Marshal(&command.WrappedRequest{
		KeyStoreID:  vars[keyStoreVarName],
		KeyID:       vars[keyVarName],
		User:        req.Header.Get("Kms-User"),
		SecretShare: secret,
		Request:     buf.Bytes(),
	})
}

// ErrorResponse is an error response model.
type ErrorResponse struct {
	Message string `json:"message"`
}

func sendError(rw http.ResponseWriter, e error) {
	rw.WriteHeader(errors.StatusCodeFromError(e))

	if err := json.NewEncoder(rw).Encode(ErrorResponse{Message: e.Error()}); err != nil {
		logger.Errorf("send error response: %v", e)
	}
}
