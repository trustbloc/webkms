/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	arieskms "github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/piprate/json-gold/ld"
	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/edge-core/pkg/zcapld"

	zcapld2 "github.com/trustbloc/kms/pkg/auth/zcapld"
	"github.com/trustbloc/kms/pkg/internal/support"
	"github.com/trustbloc/kms/pkg/kms"
)

// HTTP params.
const (
	keystoreIDQueryParam = "keystoreID"
	keyIDQueryParam      = "keyID"
)

// Endpoints.
const (
	keysPath        = "/keys"
	capabilityPath  = "/capability"
	exportPath      = "/export"
	importPath      = "/import"
	signPath        = "/sign"
	verifyPath      = "/verify"
	encryptPath     = "/encrypt"
	decryptPath     = "/decrypt"
	computeMACPath  = "/computemac"
	verifyMACPath   = "/verifymac"
	wrapPath        = "/wrap"
	unwrapPath      = "/unwrap"
	easyPath        = "/easy"
	easyOpenPath    = "/easyopen"
	sealOpenPath    = "/sealopen"
	signMultiPath   = "/signmulti"
	verifyMultiPath = "/verifymulti"
	deriveProofPath = "/deriveproof"
	verifyProofPath = "/verifyproof"

	// KMSBasePath is the base path for all KMS endpoints.
	KMSBasePath        = "/kms"
	keystoresEndpoint  = "/keystores"
	keystoreEndpoint   = keystoresEndpoint + "/{" + keystoreIDQueryParam + "}"
	keysEndpoint       = keystoreEndpoint + keysPath
	capabilityEndpoint = keystoreEndpoint + capabilityPath
	keyEndpoint        = keysEndpoint + "/{" + keyIDQueryParam + "}"
	exportEndpoint     = keyEndpoint + exportPath
	importEndpoint     = keystoreEndpoint + importPath // kms/keystores/{keystoreID}/import
	signEndpoint       = keyEndpoint + signPath
	verifyEndpoint     = keyEndpoint + verifyPath
	encryptEndpoint    = keyEndpoint + encryptPath
	decryptEndpoint    = keyEndpoint + decryptPath
	computeMACEndpoint = keyEndpoint + computeMACPath
	verifyMACEndpoint  = keyEndpoint + verifyMACPath
	wrapEndpoint       = keystoreEndpoint + wrapPath // kms/keystores/{keystoreID}/wrap
	unwrapEndpoint     = keyEndpoint + unwrapPath    // kms/keystores/{keystoreID}/keys/{keyID}/unwrap

	easyEndpoint     = keyEndpoint + easyPath
	easyOpenEndpoint = keystoreEndpoint + easyOpenPath
	sealOpenEndpoint = keystoreEndpoint + sealOpenPath

	signMultiEndpoint   = keyEndpoint + signMultiPath
	verifyMultiEndpoint = keyEndpoint + verifyMultiPath
	deriveProofEndpoint = keyEndpoint + deriveProofPath
	verifyProofEndpoint = keyEndpoint + verifyProofPath
)

// Error messages.
const (
	receivedBadRequest         = "Received bad request: %s"
	createKeystoreFailure      = "Failed to create a keystore: %s"
	resolveKeystoreFailure     = "Failed to resolve a keystore: %s"
	getKeystoreFailure         = "Failed to get a keystore: %s"
	saveKeystoreFailure        = "Failed to get a keystore: %s"
	createKeyFailure           = "Failed to create a key: %s"
	createAndExportKeyFailure  = "Failed to create and export a key: %s"
	exportKeyFailure           = "Failed to export a public key: %s"
	importKeyFailure           = "Failed to import a private key: %s"
	signMessageFailure         = "Failed to sign a message: %s"
	verifyMessageFailure       = "Failed to verify a message: %s"
	encryptMessageFailure      = "Failed to encrypt a message: %s"
	decryptMessageFailure      = "Failed to decrypt a message: %s"
	computeMACFailure          = "Failed to compute MAC: %s"
	verifyMACFailure           = "Failed to verify MAC: %s"
	wrapMessageFailure         = "Failed to wrap a key: %s"
	unwrapMessageFailure       = "Failed to unwrap a key: %s"
	createZCAPFailure          = "Failed to create zcap: %s"
	easyMessageFailure         = "Failed to easy a message: %s"
	easyOpenMessageFailure     = "Failed to easyOpen a message: %s"
	sealOpenPayloadFailure     = "Failed to sealOpen a payload: %s"
	signMultiMessagesFailure   = "Failed to sign messages: %s"
	verifyMultiMessagesFailure = "Failed to verify messages: %s"
	deriveProofFailure         = "Failed to derive proof: %s"
	verifyProofFailure         = "Failed to verify proof: %s"
)

const (
	actionCreateKey       = "createKey"
	actionExportKey       = "exportKey"
	actionImportKey       = "importKey"
	actionSign            = "sign"
	actionVerify          = "verify"
	actionWrap            = "wrap"
	actionUnwrap          = "unwrap"
	actionComputeMac      = "computeMAC"
	actionVerifyMAC       = "verifyMAC"
	actionEncrypt         = "encrypt"
	actionDecrypt         = "decrypt"
	actionStoreCapability = "updateEDVCapability"
	actionEasy            = "easy"
	actionEasyOpen        = "easyOpen"
	actionSealOpen        = "sealOpen"
	actionSignMulti       = "signMulti"
	actionVerifyMulti     = "verifyMulti"
	actionDeriveProof     = "deriveProof"
	actionVerifyProof     = "verifyProof"
)

// Handler defines an HTTP handler for the API endpoint.
type Handler interface {
	Path() string
	Method() string
	Handle() http.HandlerFunc
	Name() string
}

type authService interface {
	CreateDIDKey(context.Context) (string, error)
	NewCapability(ctx context.Context, options ...zcapld.CapabilityOption) (*zcapld.Capability, error)
	KMS() arieskms.KeyManager
	Crypto() crypto.Crypto
	Resolve(string) (*zcapld.Capability, error)
}

// Operation holds dependencies for handlers.
type Operation struct {
	authService      authService
	kmsService       kms.Service
	cryptoBoxCreator func(keyManager arieskms.KeyManager) (arieskms.CryptoBox, error)
	jsonLDLoader     ld.DocumentLoader
	logger           log.Logger
	baseURL          string
	vdrResolver      zcapld.VDRResolver
}

// Config defines configuration for KMS operations.
type Config struct {
	AuthService      authService
	KMSService       kms.Service
	CryptoBoxCreator func(keyManager arieskms.KeyManager) (arieskms.CryptoBox, error)
	JSONLDLoader     ld.DocumentLoader
	Logger           log.Logger
	BaseURL          string
	VDRResolver      zcapld.VDRResolver
}

// New returns a new Operation instance.
func New(config *Config) (*Operation, error) {
	op := &Operation{
		authService:      config.AuthService,
		kmsService:       config.KMSService,
		cryptoBoxCreator: config.CryptoBoxCreator,
		jsonLDLoader:     config.JSONLDLoader,
		logger:           config.Logger,
		baseURL:          config.BaseURL,
		vdrResolver:      config.VDRResolver,
	}

	return op, nil
}

// GetRESTHandlers gets handlers available for the kms REST API.
func (o *Operation) GetRESTHandlers() []Handler {
	return []Handler{
		support.NewHTTPHandler(keystoresEndpoint, keystoresEndpoint, http.MethodPost, o.createKeystoreHandler),
		support.NewHTTPHandler(keysEndpoint, keysEndpoint, http.MethodPost, o.createKeyHandler),
		support.NewHTTPHandler(capabilityEndpoint, capabilityEndpoint, http.MethodPost, o.updateCapabilityHandler),
		support.NewHTTPHandler(exportEndpoint, exportEndpoint, http.MethodGet, o.exportKeyHandler),
		support.NewHTTPHandler(importEndpoint, importEndpoint, http.MethodPost, o.importKeyHandler),
		support.NewHTTPHandler(signEndpoint, signEndpoint, http.MethodPost, o.signHandler),
		support.NewHTTPHandler(verifyEndpoint, verifyEndpoint, http.MethodPost, o.verifyHandler),
		support.NewHTTPHandler(encryptEndpoint, encryptEndpoint, http.MethodPost, o.encryptHandler),
		support.NewHTTPHandler(decryptEndpoint, decryptEndpoint, http.MethodPost, o.decryptHandler),
		support.NewHTTPHandler(computeMACEndpoint, computeMACEndpoint, http.MethodPost, o.computeMACHandler),
		support.NewHTTPHandler(verifyMACEndpoint, verifyMACEndpoint, http.MethodPost, o.verifyMACHandler),
		support.NewHTTPHandler(wrapEndpoint, wrapEndpoint, http.MethodPost, o.wrapHandler),
		support.NewHTTPHandler(unwrapEndpoint, unwrapEndpoint, http.MethodPost, o.unwrapHandler),
		// CryptoBox operations
		support.NewHTTPHandler(easyEndpoint, easyEndpoint, http.MethodPost, o.easyHandler),
		support.NewHTTPHandler(easyOpenEndpoint, easyOpenEndpoint, http.MethodPost, o.easyOpenHandler),
		support.NewHTTPHandler(sealOpenEndpoint, sealOpenEndpoint, http.MethodPost, o.sealOpenHandler),
		// BBS+ operations
		support.NewHTTPHandler(signMultiEndpoint, signMultiEndpoint, http.MethodPost, o.signMultiHandler),
		support.NewHTTPHandler(verifyMultiEndpoint, verifyMultiEndpoint, http.MethodPost, o.verifyMultiHandler),
		support.NewHTTPHandler(deriveProofEndpoint, deriveProofEndpoint, http.MethodPost, o.deriveProofHandler),
		support.NewHTTPHandler(verifyProofEndpoint, verifyProofEndpoint, http.MethodPost, o.verifyProofHandler),
	}
}

// swagger:route POST /kms/keystores keystore createKeystoreReq
//
// Creates a new Keystore.
//
// Responses:
//        201: createKeystoreResp
//    default: errorResp
func (o *Operation) createKeystoreHandler(rw http.ResponseWriter, req *http.Request) {
	o.logger.Debugf("handling request: %s", req.URL.String())

	var request createKeystoreReq
	if ok := o.parseRequest(&request, rw, req); !ok {
		return
	}

	keystoreData, err := o.kmsService.CreateKeystore(request.Controller, request.VaultID)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusInternalServerError, createKeystoreFailure, err)

		return
	}

	didKey, err := o.authService.CreateDIDKey(req.Context())
	if err != nil {
		o.writeErrorResponse(rw, http.StatusInternalServerError, createKeystoreFailure, err)

		return
	}

	resource := keystoreLocation(o.baseURL, keystoreData.ID)

	zcap, err := o.newCompressedZCAP(req.Context(), resource, keystoreData.Controller)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusInternalServerError, createZCAPFailure, err)

		return
	}

	rw.Header().Set("Location", resource)
	rw.Header().Set("Edvdidkey", didKey)
	rw.Header().Set("X-RootCapability", zcap)
	rw.WriteHeader(http.StatusCreated)

	o.logger.Debugf("finished handling request - keystore: %s", resource)
}

// swagger:route POST /kms/keystores/{keystoreID}/keys kms createKeyReq
//
// Creates a new key.
//
// Responses:
//        201: createKeyResp
//    default: errorResp
func (o *Operation) createKeyHandler(rw http.ResponseWriter, req *http.Request) {
	o.logger.Debugf("handling request: %s", req.URL.String())

	k, err := o.kmsService.ResolveKeystore(req)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusInternalServerError, resolveKeystoreFailure, err)

		return
	}

	var request createKeyReq
	if ok := o.parseRequest(&request, rw, req); !ok {
		return
	}

	keystoreID := mux.Vars(req)[keystoreIDQueryParam]

	var (
		keyID    string
		keyBytes []byte
	)

	if request.ExportKey {
		keyID, keyBytes, err = k.CreateAndExportKey(arieskms.KeyType(request.KeyType))
		if err != nil {
			o.writeErrorResponse(rw, http.StatusInternalServerError, createAndExportKeyFailure, err)

			return
		}
	} else {
		keyID, err = k.CreateKey(arieskms.KeyType(request.KeyType))
		if err != nil {
			o.writeErrorResponse(rw, http.StatusInternalServerError, createKeyFailure, err)

			return
		}
	}

	location := keyLocation(o.baseURL, keystoreID, keyID)

	rw.Header().Set("Location", location)
	rw.WriteHeader(http.StatusCreated)

	// refer - https://github.com/trustbloc/kms/issues/114
	o.writeResponse(rw, createKeyResp{
		Location:  location,
		PublicKey: base64.URLEncoding.EncodeToString(keyBytes),
	})

	o.logger.Debugf("Location: %s", location)
	o.logger.Debugf("finished handling request")
}

// swagger:route POST /kms/keystores/{keystoreID}/capability zcap updateCapabilityReq
//
// Updates ZCAP capabilities.
//
// Responses:
//        201: emptyRes
//    default: errorResp
func (o *Operation) updateCapabilityHandler(rw http.ResponseWriter, req *http.Request) {
	var request UpdateCapabilityReq
	if ok := o.parseRequest(&request, rw, req); !ok {
		return
	}

	if len(request.EDVCapability) == 0 {
		o.writeErrorResponse(rw, http.StatusBadRequest, "edvCapability is empty",
			fmt.Errorf(""))

		return
	}

	keystoreID := mux.Vars(req)[keystoreIDQueryParam]

	keystoreData, err := o.kmsService.GetKeystoreData(keystoreID)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusInternalServerError, getKeystoreFailure, err)

		return
	}

	keystoreData.EDVCapability = request.EDVCapability

	if err := o.kmsService.SaveKeystoreData(keystoreData); err != nil {
		o.writeErrorResponse(rw, http.StatusInternalServerError, saveKeystoreFailure, err)

		return
	}

	rw.WriteHeader(http.StatusOK)
}

// swagger:route GET /kms/keystores/{keystoreID}/keys/{keyID} kms exportKeyReq
//
// Exports a public key.
//
// Responses:
//        200: exportKeyResp
//    default: errorResp
func (o *Operation) exportKeyHandler(rw http.ResponseWriter, req *http.Request) {
	o.logger.Debugf("handle request: url=%s", req.RequestURI)

	k, err := o.kmsService.ResolveKeystore(req)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusInternalServerError, resolveKeystoreFailure, err)

		return
	}

	keyID := mux.Vars(req)[keyIDQueryParam]

	keyBytes, err := k.ExportKey(keyID)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusInternalServerError, exportKeyFailure, err)

		return
	}

	o.writeResponse(rw, exportKeyResp{
		PublicKey: base64.URLEncoding.EncodeToString(keyBytes),
	})
}

// swagger:route POST /kms/keystores/{keystoreID}/import kms importKeyReq
//
// Imports a private key.
//
// Responses:
//        201: importKeyResp
//    default: errorResp
func (o *Operation) importKeyHandler(rw http.ResponseWriter, req *http.Request) {
	o.logger.Debugf("handling request: %s", req.URL.String())

	k, err := o.kmsService.ResolveKeystore(req)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusInternalServerError, resolveKeystoreFailure, err)

		return
	}

	var request importKeyReq
	if ok := o.parseRequest(&request, rw, req); !ok {
		return
	}

	keystoreID := mux.Vars(req)[keystoreIDQueryParam]

	keyBytes, err := base64.URLEncoding.DecodeString(request.KeyBytes)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusBadRequest, receivedBadRequest, err)

		return
	}

	keyID, err := k.ImportKey(keyBytes, arieskms.KeyType(request.KeyType), request.KeyID)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusInternalServerError, importKeyFailure, err)

		return
	}

	location := keyLocation(o.baseURL, keystoreID, keyID)

	rw.Header().Set("Location", location)
	rw.WriteHeader(http.StatusCreated)

	o.writeResponse(rw, importKeyResp{
		Location: location,
	})
}

// swagger:route POST /kms/keystores/{keystoreID}/keys/{keyID}/sign kms signReq
//
// Signs a message.
//
// Responses:
//        200: signResp
//    default: errorResp
func (o *Operation) signHandler(rw http.ResponseWriter, req *http.Request) {
	o.logger.Debugf("handling request: %s", req.URL.String())

	k, err := o.kmsService.ResolveKeystore(req)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusInternalServerError, resolveKeystoreFailure, err)

		return
	}

	var request signReq
	if ok := o.parseRequest(&request, rw, req); !ok {
		return
	}

	keyID := mux.Vars(req)[keyIDQueryParam]

	kh, err := k.GetKeyHandle(keyID)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusInternalServerError, signMessageFailure, err)

		return
	}

	message, err := base64.URLEncoding.DecodeString(request.Message)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusBadRequest, receivedBadRequest, err)

		return
	}

	signature, err := o.kmsService.Sign(message, kh)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusInternalServerError, signMessageFailure, err)

		return
	}

	o.writeResponse(rw, signResp{
		Signature: base64.URLEncoding.EncodeToString(signature),
	})

	o.logger.Debugf("finished handling request: %s", req.URL.String())
}

// swagger:route POST /kms/keystores/{keystoreID}/keys/{keyID}/verify kms verifyReq
//
// Verifies a signature for the message.
//
// Responses:
//        200: emptyRes
//    default: errorResp
func (o *Operation) verifyHandler(rw http.ResponseWriter, req *http.Request) {
	k, err := o.kmsService.ResolveKeystore(req)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusInternalServerError, resolveKeystoreFailure, err)

		return
	}

	var request verifyReq
	if ok := o.parseRequest(&request, rw, req); !ok {
		return
	}

	keyID := mux.Vars(req)[keyIDQueryParam]

	kh, err := k.GetKeyHandle(keyID)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusInternalServerError, verifyMessageFailure, err)

		return
	}

	signature, err := base64.URLEncoding.DecodeString(request.Signature)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusBadRequest, receivedBadRequest, err)

		return
	}

	message, err := base64.URLEncoding.DecodeString(request.Message)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusBadRequest, receivedBadRequest, err)

		return
	}

	err = o.kmsService.Verify(signature, message, kh)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusInternalServerError, verifyMessageFailure, err)

		return
	}

	rw.WriteHeader(http.StatusOK)
}

// swagger:route POST /kms/keystores/{keystoreID}/keys/{keyID}/encrypt kms encryptReq
//
// Encrypts a message.
//
// Responses:
//        200: encryptResp
//    default: errorResp
func (o *Operation) encryptHandler(rw http.ResponseWriter, req *http.Request) {
	k, err := o.kmsService.ResolveKeystore(req)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusInternalServerError, resolveKeystoreFailure, err)

		return
	}

	var request encryptReq
	if ok := o.parseRequest(&request, rw, req); !ok {
		return
	}

	keyID := mux.Vars(req)[keyIDQueryParam]

	kh, err := k.GetKeyHandle(keyID)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusInternalServerError, encryptMessageFailure, err)

		return
	}

	message, err := base64.URLEncoding.DecodeString(request.Message)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusBadRequest, receivedBadRequest, err)

		return
	}

	aad, err := base64.URLEncoding.DecodeString(request.AdditionalData)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusBadRequest, receivedBadRequest, err)

		return
	}

	cipherText, nonce, err := o.kmsService.Encrypt(message, aad, kh)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusInternalServerError, encryptMessageFailure, err)

		return
	}

	o.writeResponse(rw, encryptResp{
		CipherText: base64.URLEncoding.EncodeToString(cipherText),
		Nonce:      base64.URLEncoding.EncodeToString(nonce),
	})
}

// swagger:route POST /kms/keystores/{keystoreID}/keys/{keyID}/decrypt kms decryptReq
//
// Decrypts a cipher.
//
// Responses:
//        200: decryptResp
//    default: errorResp
func (o *Operation) decryptHandler(rw http.ResponseWriter, req *http.Request) {
	k, err := o.kmsService.ResolveKeystore(req)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusInternalServerError, resolveKeystoreFailure, err)

		return
	}

	keyID := mux.Vars(req)[keyIDQueryParam]

	kh, err := k.GetKeyHandle(keyID)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusInternalServerError, decryptMessageFailure, err)

		return
	}

	var request decryptReq
	if ok := o.parseRequest(&request, rw, req); !ok {
		return
	}

	cipherText, err := base64.URLEncoding.DecodeString(request.CipherText)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusBadRequest, receivedBadRequest, err)

		return
	}

	aad, err := base64.URLEncoding.DecodeString(request.AdditionalData)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusBadRequest, receivedBadRequest, err)

		return
	}

	nonce, err := base64.URLEncoding.DecodeString(request.Nonce)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusBadRequest, receivedBadRequest, err)

		return
	}

	plainText, err := o.kmsService.Decrypt(cipherText, aad, nonce, kh)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusInternalServerError, decryptMessageFailure, err)

		return
	}

	o.writeResponse(rw, decryptResp{
		PlainText: base64.URLEncoding.EncodeToString(plainText),
	})
}

// swagger:route POST /kms/keystores/{keystoreID}/keys/{keyID}/computemac kms computeMACReq
//
// Computes MAC for data.
//
// Responses:
//        200: computeMACResp
//    default: errorResp
func (o *Operation) computeMACHandler(rw http.ResponseWriter, req *http.Request) {
	k, err := o.kmsService.ResolveKeystore(req)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusInternalServerError, resolveKeystoreFailure, err)

		return
	}

	keyID := mux.Vars(req)[keyIDQueryParam]

	kh, err := k.GetKeyHandle(keyID)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusInternalServerError, computeMACFailure, err)

		return
	}

	var request computeMACReq
	if ok := o.parseRequest(&request, rw, req); !ok {
		return
	}

	data, err := base64.URLEncoding.DecodeString(request.Data)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusBadRequest, receivedBadRequest, err)

		return
	}

	mac, err := o.kmsService.ComputeMAC(data, kh)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusInternalServerError, computeMACFailure, err)

		return
	}

	o.writeResponse(rw, computeMACResp{
		MAC: base64.URLEncoding.EncodeToString(mac),
	})
}

// swagger:route POST /kms/keystores/{keystoreID}/keys/{keyID}/verifymac kms verifyMACReq
//
// Verifies MAC for data.
//
// Responses:
//        200: emptyRes
//    default: errorResp
func (o *Operation) verifyMACHandler(rw http.ResponseWriter, req *http.Request) {
	k, err := o.kmsService.ResolveKeystore(req)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusInternalServerError, resolveKeystoreFailure, err)

		return
	}

	keyID := mux.Vars(req)[keyIDQueryParam]

	kh, err := k.GetKeyHandle(keyID)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusInternalServerError, verifyMACFailure, err)

		return
	}

	var request verifyMACReq
	if ok := o.parseRequest(&request, rw, req); !ok {
		return
	}

	mac, err := base64.URLEncoding.DecodeString(request.MAC)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusBadRequest, receivedBadRequest, err)

		return
	}

	data, err := base64.URLEncoding.DecodeString(request.Data)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusBadRequest, receivedBadRequest, err)

		return
	}

	err = o.kmsService.VerifyMAC(mac, data, kh)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusInternalServerError, verifyMACFailure, err)

		return
	}

	rw.WriteHeader(http.StatusOK)
}

// swagger:route POST /kms/keystores/{keystoreID}/wrap kms wrapReq
//
// Wraps CEK for the recipient.
//
// Responses:
//        200: wrapResp
//    default: errorResp
func (o *Operation) wrapHandler(rw http.ResponseWriter, req *http.Request) {
	var request wrapReq
	if ok := o.parseRequest(&request, rw, req); !ok {
		return
	}

	cek, err := base64.URLEncoding.DecodeString(request.CEK)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusBadRequest, receivedBadRequest, err)

		return
	}

	apu, err := base64.URLEncoding.DecodeString(request.APU)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusBadRequest, receivedBadRequest, err)

		return
	}

	apv, err := base64.URLEncoding.DecodeString(request.APV)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusBadRequest, receivedBadRequest, err)

		return
	}

	recPubKey, err := unmarshalPublicKey(&request.RecipientPubKey)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusBadRequest, receivedBadRequest, err)

		return
	}

	wrappedKey, err := o.kmsService.WrapKey(cek, apu, apv, recPubKey)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusInternalServerError, wrapMessageFailure, err)

		return
	}

	o.writeResponse(rw, wrapResp{recipientWrappedKey{
		KID:          base64.URLEncoding.EncodeToString([]byte(wrappedKey.KID)),
		EncryptedCEK: base64.URLEncoding.EncodeToString(wrappedKey.EncryptedCEK),
		EPK:          marshalPublicKey(&wrappedKey.EPK),
		Alg:          base64.URLEncoding.EncodeToString([]byte(wrappedKey.Alg)),
		APU:          base64.URLEncoding.EncodeToString(wrappedKey.APU),
		APV:          base64.URLEncoding.EncodeToString(wrappedKey.APV),
	}})
}

// swagger:route POST /kms/keystores/{keystoreID}/keys/{keyID}/unwrap kms unwrapReq
//
// Unwraps a key.
//
// Responses:
//        200: unwrapResp
//    default: errorResp
//nolint:gocyclo // TODO refactor
func (o *Operation) unwrapHandler(rw http.ResponseWriter, req *http.Request) { //nolint:funlen // readability
	k, err := o.kmsService.ResolveKeystore(req)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusInternalServerError, resolveKeystoreFailure, err)

		return
	}

	var request unwrapReq
	if ok := o.parseRequest(&request, rw, req); !ok {
		return
	}

	keyID := mux.Vars(req)[keyIDQueryParam]

	kid, err := base64.URLEncoding.DecodeString(request.WrappedKey.KID)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusBadRequest, receivedBadRequest, err)

		return
	}

	enc, err := base64.URLEncoding.DecodeString(request.WrappedKey.EncryptedCEK)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusBadRequest, receivedBadRequest, err)

		return
	}

	epk, err := unmarshalPublicKey(&request.WrappedKey.EPK)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusBadRequest, receivedBadRequest, err)

		return
	}

	alg, err := base64.URLEncoding.DecodeString(request.WrappedKey.Alg)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusBadRequest, receivedBadRequest, err)

		return
	}

	apu, err := base64.URLEncoding.DecodeString(request.WrappedKey.APU)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusBadRequest, receivedBadRequest, err)

		return
	}

	apv, err := base64.URLEncoding.DecodeString(request.WrappedKey.APV)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusBadRequest, receivedBadRequest, err)

		return
	}

	recipientWK := &crypto.RecipientWrappedKey{
		KID:          string(kid),
		EncryptedCEK: enc,
		EPK:          *epk,
		Alg:          string(alg),
		APU:          apu,
		APV:          apv,
	}

	kh, err := k.GetKeyHandle(keyID)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusInternalServerError, unwrapMessageFailure, err)

		return
	}

	// TODO(#90): Implement support for Authcrypt unwrapping
	cek, err := o.kmsService.UnwrapKey(recipientWK, kh)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusInternalServerError, unwrapMessageFailure, err)

		return
	}

	o.writeResponse(rw, unwrapResp{Key: base64.URLEncoding.EncodeToString(cek)})
}

// swagger:route POST /kms/keystores/{keystoreID}/keys/{keyID}/signmulti kms signMultiReq
//
// Creates a BBS+ signature of messages.
//
// Responses:
//        200: signResp
//    default: errorResp
func (o *Operation) signMultiHandler(rw http.ResponseWriter, req *http.Request) {
	o.logger.Debugf("handling request: %s", req.URL.String())

	k, err := o.kmsService.ResolveKeystore(req)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusInternalServerError, resolveKeystoreFailure, err)

		return
	}

	keyID := mux.Vars(req)[keyIDQueryParam]

	kh, err := k.GetKeyHandle(keyID)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusInternalServerError, signMultiMessagesFailure, err)

		return
	}

	var request signMultiReq
	if ok := o.parseRequest(&request, rw, req); !ok {
		return
	}

	var messages [][]byte

	for _, msg := range request.Messages {
		m, e := base64.URLEncoding.DecodeString(msg)
		if e != nil {
			o.writeErrorResponse(rw, http.StatusBadRequest, receivedBadRequest, e)

			return
		}

		messages = append(messages, m)
	}

	signature, err := o.kmsService.SignMulti(messages, kh)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusInternalServerError, signMultiMessagesFailure, err)

		return
	}

	o.writeResponse(rw, signResp{
		Signature: base64.URLEncoding.EncodeToString(signature),
	})

	o.logger.Debugf("finished handling request: %s", req.URL.String())
}

// swagger:route POST /kms/keystores/{keystoreID}/keys/{keyID}/verifymulti kms verifyMultiReq
//
// Verifies a signature of messages (BBS+).
//
// Responses:
//        200: emptyRes
//    default: errorResp
func (o *Operation) verifyMultiHandler(rw http.ResponseWriter, req *http.Request) {
	k, err := o.kmsService.ResolveKeystore(req)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusInternalServerError, resolveKeystoreFailure, err)

		return
	}

	keyID := mux.Vars(req)[keyIDQueryParam]

	kh, err := k.GetKeyHandle(keyID)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusInternalServerError, verifyMultiMessagesFailure, err)

		return
	}

	var request verifyMultiReq
	if ok := o.parseRequest(&request, rw, req); !ok {
		return
	}

	signature, err := base64.URLEncoding.DecodeString(request.Signature)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusBadRequest, receivedBadRequest, err)

		return
	}

	var messages [][]byte

	for _, msg := range request.Messages {
		m, e := base64.URLEncoding.DecodeString(msg)
		if e != nil {
			o.writeErrorResponse(rw, http.StatusBadRequest, receivedBadRequest, e)

			return
		}

		messages = append(messages, m)
	}

	err = o.kmsService.VerifyMulti(messages, signature, kh)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusInternalServerError, verifyMultiMessagesFailure, err)

		return
	}

	rw.WriteHeader(http.StatusOK)
}

// swagger:route POST /kms/keystores/{keystoreID}/keys/{keyID}/deriveproof kms deriveProofReq
//
// Creates a BBS+ signature proof for a list of revealed messages.
//
// Responses:
//        200: deriveProofResp
//    default: errorResp
func (o *Operation) deriveProofHandler(rw http.ResponseWriter, req *http.Request) {
	k, err := o.kmsService.ResolveKeystore(req)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusInternalServerError, resolveKeystoreFailure, err)

		return
	}

	keyID := mux.Vars(req)[keyIDQueryParam]

	kh, err := k.GetKeyHandle(keyID)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusInternalServerError, deriveProofFailure, err)

		return
	}

	var request deriveProofReq
	if ok := o.parseRequest(&request, rw, req); !ok {
		return
	}

	var messages [][]byte

	for _, msg := range request.Messages {
		m, e := base64.URLEncoding.DecodeString(msg)
		if e != nil {
			o.writeErrorResponse(rw, http.StatusBadRequest, receivedBadRequest, e)

			return
		}

		messages = append(messages, m)
	}

	signature, err := base64.URLEncoding.DecodeString(request.Signature)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusBadRequest, receivedBadRequest, err)

		return
	}

	nonce, err := base64.URLEncoding.DecodeString(request.Nonce)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusBadRequest, receivedBadRequest, err)

		return
	}

	proof, err := o.kmsService.DeriveProof(messages, signature, nonce, request.RevealedIndexes, kh)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusInternalServerError, deriveProofFailure, err)

		return
	}

	o.writeResponse(rw, deriveProofResp{
		Proof: base64.URLEncoding.EncodeToString(proof),
	})
}

// swagger:route POST /kms/keystores/{keystoreID}/keys/{keyID}/verifyproof kms verifyProofReq
//
// Verifies a BBS+ signature proof for revealed messages.
//
// Responses:
//        200: emptyRes
//    default: errorResp
func (o *Operation) verifyProofHandler(rw http.ResponseWriter, req *http.Request) {
	k, err := o.kmsService.ResolveKeystore(req)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusInternalServerError, resolveKeystoreFailure, err)

		return
	}

	keyID := mux.Vars(req)[keyIDQueryParam]

	kh, err := k.GetKeyHandle(keyID)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusInternalServerError, verifyProofFailure, err)

		return
	}

	var request verifyProofReq
	if ok := o.parseRequest(&request, rw, req); !ok {
		return
	}

	proof, err := base64.URLEncoding.DecodeString(request.Proof)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusBadRequest, receivedBadRequest, err)

		return
	}

	nonce, err := base64.URLEncoding.DecodeString(request.Nonce)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusBadRequest, receivedBadRequest, err)

		return
	}

	var messages [][]byte

	for _, msg := range request.Messages {
		m, e := base64.URLEncoding.DecodeString(msg)
		if e != nil {
			o.writeErrorResponse(rw, http.StatusBadRequest, receivedBadRequest, e)

			return
		}

		messages = append(messages, m)
	}

	err = o.kmsService.VerifyProof(messages, proof, nonce, kh)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusInternalServerError, verifyProofFailure, err)

		return
	}

	rw.WriteHeader(http.StatusOK)
}

func (o *Operation) parseRequest(parsedReq interface{}, rw http.ResponseWriter, req *http.Request) bool {
	o.logger.Debugf("handle request: url=%s", req.RequestURI)

	if err := json.NewDecoder(req.Body).Decode(&parsedReq); err != nil {
		o.writeErrorResponse(rw, http.StatusBadRequest, receivedBadRequest, err)

		return false
	}

	return true
}

func (o *Operation) writeErrorResponse(rw http.ResponseWriter, status int, messageFormat string, err error) {
	o.logger.Errorf(messageFormat, err)

	rw.WriteHeader(status)

	e := json.NewEncoder(rw).Encode(errorResp{
		Message: fmt.Sprintf(messageFormat, err),
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

func (o *Operation) newCompressedZCAP(ctx context.Context, resource, controller string) (string, error) {
	zcap, err := o.authService.NewCapability(ctx,
		zcapld.WithInvocationTarget(resource, "urn:kms:keystore"),
		zcapld.WithInvoker(controller),
		zcapld.WithID(resource),
		zcapld.WithAllowedActions(allActions()...),
	)
	if err != nil {
		return "", fmt.Errorf("failed to create zcap: %w", err)
	}

	compressed, err := zcapld2.CompressZCAP(zcap)
	if err != nil {
		return "", fmt.Errorf("failed to compress zcap: %w", err)
	}

	return compressed, nil
}

func unmarshalPublicKey(k *publicKey) (*crypto.PublicKey, error) {
	kid, err := base64.URLEncoding.DecodeString(k.KID)
	if err != nil {
		return nil, fmt.Errorf("decode key ID: %w", err)
	}

	x, err := base64.URLEncoding.DecodeString(k.X)
	if err != nil {
		return nil, fmt.Errorf("decode x: %w", err)
	}

	y, err := base64.URLEncoding.DecodeString(k.Y)
	if err != nil {
		return nil, fmt.Errorf("decode y: %w", err)
	}

	curve, err := base64.URLEncoding.DecodeString(k.Curve)
	if err != nil {
		return nil, fmt.Errorf("decode curve: %w", err)
	}

	typ, err := base64.URLEncoding.DecodeString(k.Type)
	if err != nil {
		return nil, fmt.Errorf("decode type: %w", err)
	}

	return &crypto.PublicKey{
		KID:   string(kid),
		X:     x,
		Y:     y,
		Curve: string(curve),
		Type:  string(typ),
	}, nil
}

func marshalPublicKey(k *crypto.PublicKey) publicKey {
	return publicKey{
		KID:   base64.URLEncoding.EncodeToString([]byte(k.KID)),
		X:     base64.URLEncoding.EncodeToString(k.X),
		Y:     base64.URLEncoding.EncodeToString(k.Y),
		Curve: base64.URLEncoding.EncodeToString([]byte(k.Curve)),
		Type:  base64.URLEncoding.EncodeToString([]byte(k.Type)),
	}
}

func keystoreLocation(baseURL, keystoreID string) string {
	// {baseURL}/kms/keystores/{keystoreID}
	return fmt.Sprintf(
		"%s%s%s",
		baseURL,
		KMSBasePath,
		strings.ReplaceAll(keystoreEndpoint, "{keystoreID}", keystoreID),
	)
}

func keyLocation(baseURL, keystoreID, keyID string) string {
	// {baseURL}/kms/keystores/{keystoreID}/keys/{keyID}
	r := strings.NewReplacer(
		"{keystoreID}", keystoreID,
		"{keyID}", keyID)

	return fmt.Sprintf("%s%s%s", baseURL, KMSBasePath, r.Replace(keyEndpoint))
}

func allActions() []string {
	return []string{
		actionCreateKey,
		actionExportKey,
		actionImportKey,
		actionSign,
		actionVerify,
		actionWrap,
		actionUnwrap,
		actionComputeMac,
		actionVerifyMAC,
		actionEncrypt,
		actionDecrypt,
		actionStoreCapability,
		actionEasy,
		actionEasyOpen,
		actionSealOpen,
		actionSignMulti,
		actionVerifyMulti,
		actionDeriveProof,
		actionVerifyProof,
	}
}
