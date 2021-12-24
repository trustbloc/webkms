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
	KeyStoreVarName = "keystore"
	keyVarName      = "key"
	BaseV1Path      = "/v1"
	KeyStorePath    = BaseV1Path + "/keystores"
	DIDPath         = KeyStorePath + "/did"
	KeyPath         = KeyStorePath + "/{" + KeyStoreVarName + "}/keys"
	ExportKeyPath   = KeyPath + "/{" + keyVarName + "}/export"
	RotateKeyPath   = KeyPath + "/{" + keyVarName + "}/rotate"
	SignPath        = KeyPath + "/{" + keyVarName + "}/sign"
	VerifyPath      = KeyPath + "/{" + keyVarName + "}/verify"
	EncryptPath     = KeyPath + "/{" + keyVarName + "}/encrypt"
	DecryptPath     = KeyPath + "/{" + keyVarName + "}/decrypt"
	ComputeMACPath  = KeyPath + "/{" + keyVarName + "}/computemac"
	VerifyMACPath   = KeyPath + "/{" + keyVarName + "}/verifymac"
	SignMultiPath   = KeyPath + "/{" + keyVarName + "}/signmulti"
	VerifyMultiPath = KeyPath + "/{" + keyVarName + "}/verifymulti"
	DeriveProofPath = KeyPath + "/{" + keyVarName + "}/deriveproof"
	VerifyProofPath = KeyPath + "/{" + keyVarName + "}/verifyproof"
	EasyPath        = KeyPath + "/{" + keyVarName + "}/easy"
	EasyOpenPath    = KeyStorePath + "/{" + KeyStoreVarName + "}/easyopen"
	SealOpenPath    = KeyStorePath + "/{" + KeyStoreVarName + "}/sealopen"
	WrapKeyPath     = KeyStorePath + "/{" + KeyStoreVarName + "}/wrap"
	WrapKeyAEPath   = KeyPath + "/{" + keyVarName + "}/wrap"
	UnwrapKeyPath   = KeyPath + "/{" + keyVarName + "}/unwrap"
	HealthCheckPath = "/healthcheck"
)

const (
	contentType       = "Content-Type"
	applicationJSON   = "application/json"
	authUserHeader    = "Auth-User"
	secretShareHeader = "Secret-Share"
)

var logger = log.New("controller/rest")

// Cmd defines command methods.
type Cmd interface {
	CreateDID(w io.Writer, r io.Reader) error
	CreateKeyStore(w io.Writer, r io.Reader) error
	CreateKey(w io.Writer, r io.Reader) error
	ExportKey(w io.Writer, r io.Reader) error
	RotateKey(w io.Writer, r io.Reader) error
	ImportKey(w io.Writer, r io.Reader) error
	Sign(w io.Writer, r io.Reader) error
	Verify(w io.Writer, r io.Reader) error
	Encrypt(w io.Writer, r io.Reader) error
	Decrypt(w io.Writer, r io.Reader) error
	ComputeMAC(w io.Writer, r io.Reader) error
	VerifyMAC(w io.Writer, r io.Reader) error
	SignMulti(w io.Writer, r io.Reader) error
	VerifyMulti(w io.Writer, r io.Reader) error
	DeriveProof(w io.Writer, r io.Reader) error
	VerifyProof(w io.Writer, r io.Reader) error
	Easy(w io.Writer, r io.Reader) error
	EasyOpen(w io.Writer, r io.Reader) error
	SealOpen(w io.Writer, r io.Reader) error
	WrapKey(w io.Writer, r io.Reader) error
	UnwrapKey(w io.Writer, r io.Reader) error
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
		NewHTTPHandler(DIDPath, http.MethodPost, o.CreateDID, command.ActionCreateDID, false),
		NewHTTPHandler(KeyStorePath, http.MethodPost, o.CreateKeyStore, command.ActionCreateKeyStore, false),
		NewHTTPHandler(KeyPath, http.MethodPost, o.CreateKey, command.ActionCreateKey, true),
		NewHTTPHandler(KeyPath, http.MethodPut, o.ImportKey, command.ActionImportKey, true),
		NewHTTPHandler(ExportKeyPath, http.MethodGet, o.ExportKey, command.ActionExportKey, true),
		NewHTTPHandler(RotateKeyPath, http.MethodPost, o.RotateKey, command.ActionRotateKey, true),
		NewHTTPHandler(SignPath, http.MethodPost, o.Sign, command.ActionSign, true),
		NewHTTPHandler(VerifyPath, http.MethodPost, o.Verify, command.ActionVerify, true),
		NewHTTPHandler(EncryptPath, http.MethodPost, o.Encrypt, command.ActionEncrypt, true),
		NewHTTPHandler(DecryptPath, http.MethodPost, o.Decrypt, command.ActionDecrypt, true),
		NewHTTPHandler(ComputeMACPath, http.MethodPost, o.ComputeMAC, command.ActionComputeMac, true),
		NewHTTPHandler(VerifyMACPath, http.MethodPost, o.VerifyMAC, command.ActionVerifyMAC, true),
		NewHTTPHandler(SignMultiPath, http.MethodPost, o.SignMulti, command.ActionSignMulti, true),
		NewHTTPHandler(VerifyMultiPath, http.MethodPost, o.VerifyMulti, command.ActionVerifyMulti, true),
		NewHTTPHandler(DeriveProofPath, http.MethodPost, o.DeriveProof, command.ActionDeriveProof, true),
		NewHTTPHandler(VerifyProofPath, http.MethodPost, o.VerifyProof, command.ActionVerifyProof, true),
		NewHTTPHandler(EasyPath, http.MethodPost, o.Easy, command.ActionEasy, true),
		NewHTTPHandler(EasyOpenPath, http.MethodPost, o.EasyOpen, command.ActionEasyOpen, true),
		NewHTTPHandler(SealOpenPath, http.MethodPost, o.SealOpen, command.ActionSealOpen, true),
		NewHTTPHandler(WrapKeyPath, http.MethodPost, o.WrapKey, command.ActionWrap, true),
		NewHTTPHandler(WrapKeyAEPath, http.MethodPost, o.WrapKeyAE, command.ActionWrap, true),
		NewHTTPHandler(UnwrapKeyPath, http.MethodPost, o.UnwrapKey, command.ActionUnwrap, true),
		NewHTTPHandler(HealthCheckPath, http.MethodGet, o.HealthCheck, "", false),
	}
}

// CreateDID swagger:route POST /v1/keystores/did kms createDIDReq
//
// Creates a DID.
//
// Responses:
//        201: createDIDResp
//    default: errorResp
func (o *Operation) CreateDID(rw http.ResponseWriter, req *http.Request) {
	execute(o.cmd.CreateDID, rw, req)
}

// CreateKeyStore swagger:route POST /v1/keystores kms createKeyStoreReq
//
// Creates a new key store.
//
// Responses:
//        201: createKeyStoreResp
//    default: errorResp
func (o *Operation) CreateKeyStore(rw http.ResponseWriter, req *http.Request) {
	execute(o.cmd.CreateKeyStore, rw, req)
}

// CreateKey swagger:route POST /v1/keystores/{key_store_id}/keys kms createKeyReq
//
// Creates a new key.
//
// Responses:
//        201: createKeyResp
//    default: errorResp
func (o *Operation) CreateKey(rw http.ResponseWriter, req *http.Request) {
	execute(o.cmd.CreateKey, rw, req)
}

// ImportKey swagger:route PUT /v1/keystores/{key_store_id}/keys kms importKeyReq
//
// Imports a private key.
//
// Responses:
//        201: importKeyResp
//    default: errorResp
func (o *Operation) ImportKey(rw http.ResponseWriter, req *http.Request) {
	execute(o.cmd.ImportKey, rw, req)
}

// ExportKey swagger:route GET /v1/keystores/{key_store_id}/keys/{key_id} kms exportKeyReq
//
// Exports a public key.
//
// Responses:
//        200: exportKeyResp
//    default: errorResp
func (o *Operation) ExportKey(rw http.ResponseWriter, req *http.Request) {
	execute(o.cmd.ExportKey, rw, req)
}

// RotateKey swagger:route POST /v1/keystores/{key_store_id}/keys/{key_id}/rotate kms rotateKeyReq
//
// Rotate the key.
//
// Responses:
//        200: rotateKeyResp
//    default: errorResp
func (o *Operation) RotateKey(rw http.ResponseWriter, req *http.Request) {
	execute(o.cmd.RotateKey, rw, req)
}

// Sign swagger:route POST /v1/keystores/{key_store_id}/keys/{key_id}/sign crypto signReq
//
// Signs a message.
//
// Responses:
//        200: signResp
//    default: errorResp
func (o *Operation) Sign(rw http.ResponseWriter, req *http.Request) {
	execute(o.cmd.Sign, rw, req)
}

// Verify swagger:route POST /v1/keystores/{key_store_id}/keys/{key_id}/verify crypto verifyReq
//
// Verifies a signature.
//
// Responses:
//        200: verifyResp
//    default: errorResp
func (o *Operation) Verify(rw http.ResponseWriter, req *http.Request) {
	execute(o.cmd.Verify, rw, req)
}

// Encrypt swagger:route POST /v1/keystores/{key_store_id}/keys/{key_id}/encrypt crypto encryptReq
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

// Decrypt swagger:route POST /v1/keystores/{key_store_id}/keys/{key_id}/decrypt crypto decryptReq
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

// ComputeMAC swagger:route POST /v1/keystores/{key_store_id}/keys/{key_id}/computemac crypto computeMACReq
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

// VerifyMAC swagger:route POST /v1/keystores/{key_store_id}/keys/{key_id}/verifymac crypto verifyMACReq
//
// Verifies whether MAC is a correct authentication code for data.
//
// Responses:
//        200: verifyMACResp
//    default: errorResp
func (o *Operation) VerifyMAC(rw http.ResponseWriter, req *http.Request) {
	execute(o.cmd.VerifyMAC, rw, req)
}

// SignMulti swagger:route POST /v1/keystores/{key_store_id}/keys/{key_id}/signmulti crypto signMultiReq
//
// Creates a BBS+ signature of messages.
//
// Responses:
//        200: signMultiResp
//    default: errorResp
func (o *Operation) SignMulti(rw http.ResponseWriter, req *http.Request) {
	execute(o.cmd.SignMulti, rw, req)
}

// VerifyMulti swagger:route POST /v1/keystores/{key_store_id}/keys/{key_id}/verifymulti crypto verifyMultiReq
//
// Verifies a signature of messages (BBS+).
//
// Responses:
//        200: verifyMultiResp
//    default: errorResp
func (o *Operation) VerifyMulti(rw http.ResponseWriter, req *http.Request) {
	execute(o.cmd.VerifyMulti, rw, req)
}

// DeriveProof swagger:route POST /v1/keystores/{key_store_id}/keys/{key_id}/deriveproof crypto deriveProofReq
//
// Creates a BBS+ signature proof for a list of revealed messages.
//
// Responses:
//        200: deriveProofResp
//    default: errorResp
func (o *Operation) DeriveProof(rw http.ResponseWriter, req *http.Request) {
	execute(o.cmd.DeriveProof, rw, req)
}

// VerifyProof swagger:route POST /v1/keystores/{key_store_id}/keys/{key_id}/verifyproof crypto verifyProofReq
//
// Verifies a BBS+ signature proof for revealed messages.
//
// Responses:
//        200: verifyProofResp
//    default: errorResp
func (o *Operation) VerifyProof(rw http.ResponseWriter, req *http.Request) {
	execute(o.cmd.VerifyProof, rw, req)
}

// Easy swagger:route POST /v1/keystores/{key_store_id}/keys/{key_id}/easy crypto easyReq
//
// Seals a message.
//
// Responses:
//        200: easyResp
//    default: errorResp
func (o *Operation) Easy(rw http.ResponseWriter, req *http.Request) {
	execute(o.cmd.Easy, rw, req)
}

// EasyOpen swagger:route POST /v1/keystores/{key_store_id}/easyopen crypto easyOpenReq
//
// Unseals a message sealed with Easy.
//
// Responses:
//        200: easyOpenResp
//    default: errorResp
func (o *Operation) EasyOpen(rw http.ResponseWriter, req *http.Request) {
	execute(o.cmd.EasyOpen, rw, req)
}

// SealOpen swagger:route POST /v1/keystores/{key_store_id}/sealopen crypto sealOpenReq
//
// Decrypts a payload encrypted with Seal.
//
// Responses:
//        200: sealOpenResp
//    default: errorResp
func (o *Operation) SealOpen(rw http.ResponseWriter, req *http.Request) {
	execute(o.cmd.SealOpen, rw, req)
}

// WrapKey swagger:route POST /v1/keystores/{key_store_id}/wrap crypto wrapKeyReq
//
// Wraps CEK using ECDH-ES key wrapping (Anoncrypt).
//
// Responses:
//        200: wrapKeyResp
//    default: errorResp
func (o *Operation) WrapKey(rw http.ResponseWriter, req *http.Request) {
	execute(o.cmd.WrapKey, rw, req)
}

// WrapKeyAE swagger:route POST /v1/keystores/{key_store_id}/keys/{key_id}/wrap crypto wrapKeyAEReq
//
// Wraps CEK using ECDH-1PU key wrapping (Authcrypt).
//
// Responses:
//        200: wrapKeyResp
//    default: errorResp
func (o *Operation) WrapKeyAE(rw http.ResponseWriter, req *http.Request) {
	execute(o.cmd.WrapKey, rw, req)
}

// UnwrapKey swagger:route POST /v1/keystores/{key_store_id}/keys/{key_id}/unwrap crypto unwrapKeyReq
//
// Unwraps a wrapped key.
//
// Responses:
//        200: unwrapKeyResp
//    default: errorResp
func (o *Operation) UnwrapKey(rw http.ResponseWriter, req *http.Request) {
	execute(o.cmd.UnwrapKey, rw, req)
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
		sendError(rw, fmt.Errorf("%s %s: %w", req.Method, req.RequestURI, err))
	}
}

func wrapRequest(req *http.Request) ([]byte, error) {
	var buf bytes.Buffer

	_, err := io.Copy(&buf, req.Body)
	if err != nil {
		return nil, fmt.Errorf("%w: copy request body", errors.ErrInternal)
	}

	var secret []byte

	secretHeader := req.Header.Get(secretShareHeader)

	if secretHeader != "" {
		secret, err = base64.StdEncoding.DecodeString(secretHeader)
		if err != nil {
			return nil, fmt.Errorf("%w: decode secret share from header", errors.ErrBadRequest)
		}
	}

	vars := mux.Vars(req)

	return json.Marshal(&command.WrappedRequest{
		KeyStoreID:  vars[KeyStoreVarName],
		KeyID:       vars[keyVarName],
		User:        req.Header.Get(authUserHeader),
		SecretShare: secret,
		Request:     buf.Bytes(),
	})
}

// ErrorResponse is an error response model.
type ErrorResponse struct {
	Message string `json:"message"`
}

func sendError(rw http.ResponseWriter, e error) {
	logger.Errorf("%v", e)

	rw.WriteHeader(errors.StatusCodeFromError(e))

	if err := json.NewEncoder(rw).Encode(ErrorResponse{Message: e.Error()}); err != nil {
		logger.Errorf("send error response: %v", err)
	}
}
