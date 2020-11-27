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
	"time"

	"github.com/gorilla/mux"
	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	arieskms "github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/piprate/json-gold/ld"
	"github.com/rs/xid"
	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/edge-core/pkg/zcapld"

	zcapld2 "github.com/trustbloc/hub-kms/pkg/auth/zcapld"
	"github.com/trustbloc/hub-kms/pkg/internal/support"
	"github.com/trustbloc/hub-kms/pkg/keystore"
	"github.com/trustbloc/hub-kms/pkg/kms"
)

const (
	// HTTP params.
	keystoreIDQueryParam = "keystoreID"
	keyIDQueryParam      = "keyID"

	// KMSBasePath is the base path for all KMS endpoints.
	KMSBasePath        = "/kms"
	keystoresEndpoint  = "/keystores"
	keystoreEndpoint   = keystoresEndpoint + "/{" + keystoreIDQueryParam + "}"
	keysEndpoint       = keystoreEndpoint + "/keys"
	capabilityEndpoint = keystoreEndpoint + "/capability"
	keyEndpoint        = keysEndpoint + "/{" + keyIDQueryParam + "}"
	exportEndpoint     = keyEndpoint + "/export"
	signEndpoint       = keyEndpoint + "/sign"
	verifyEndpoint     = keyEndpoint + "/verify"
	encryptEndpoint    = keyEndpoint + "/encrypt"
	decryptEndpoint    = keyEndpoint + "/decrypt"
	computeMACEndpoint = keyEndpoint + "/computemac"
	verifyMACEndpoint  = keyEndpoint + "/verifymac"
	wrapEndpoint       = keystoreEndpoint + "/wrap" // kms/keystores/{keystoreID}/wrap
	unwrapEndpoint     = keyEndpoint + "/unwrap"    // kms/keystores/{keystoreID}/keys/{keyID}/unwrap

	// Error messages.
	receivedBadRequest      = "Received bad request: %s"
	createKeystoreFailure   = "Failed to create a keystore: %s"
	getKeystoreFailure      = "Failed to get a keystore: %s"
	saveKeystoreFailure     = "Failed to get a keystore: %s"
	createKMSServiceFailure = "Failed to create a KMS service: %s"
	createKeyFailure        = "Failed to create a key: %s"
	exportKeyFailure        = "Failed to export a public key: %s"
	signMessageFailure      = "Failed to sign a message: %s"
	verifyMessageFailure    = "Failed to verify a message: %s"
	encryptMessageFailure   = "Failed to encrypt a message: %s"
	decryptMessageFailure   = "Failed to decrypt a message: %s"
	computeMACFailure       = "Failed to compute MAC: %s"
	verifyMACFailure        = "Failed to verify MAC: %s"
	wrapMessageFailure      = "Failed to wrap a key: %s"
	unwrapMessageFailure    = "Failed to unwrap a key: %s"
	createZCAPFailure       = "Failed to create zcap: %s"
)

const (
	actionCreateKey       = "createKey"
	actionExportKey       = "exportKey"
	actionSign            = "sign"
	actionVerify          = "verify"
	actionWrap            = "wrap"
	actionUnwrap          = "unwrap"
	actionComputeMac      = "computeMAC"
	actionVerifyMAC       = "verifyMAC"
	actionEncrypt         = "encrypt"
	actionDecrypt         = "decrypt"
	actionStoreCapability = "updateEDVCapability"
)

// Handler defines an HTTP handler for the API endpoint.
type Handler interface {
	Path() string
	Method() string
	Handle() http.HandlerFunc
	Name() string
}

type authService interface {
	CreateDIDKey() (string, error)
	NewCapability(options ...zcapld.CapabilityOption) (*zcapld.Capability, error)
	KMS() arieskms.KeyManager
	Crypto() crypto.Crypto
	Resolve(string) (*zcapld.Capability, error)
}

// Operation holds dependencies for handlers.
type Operation struct {
	keystoreService   keystore.Service
	kmsServiceCreator func(req *http.Request) (kms.Service, error)
	logger            log.Logger
	isEDVUsed         bool
	authService       authService
	ldDocLoader       ld.DocumentLoader
}

// Config defines configuration for KMS operations.
type Config struct {
	KeystoreService   keystore.Service
	KMSServiceCreator func(req *http.Request) (kms.Service, error)
	Logger            log.Logger
	IsEDVUsed         bool
	AuthService       authService
	LDDocumentLoader  ld.DocumentLoader
}

// New returns a new Operation instance.
func New(config *Config) *Operation {
	op := &Operation{
		keystoreService:   config.KeystoreService,
		kmsServiceCreator: config.KMSServiceCreator,
		logger:            config.Logger,
		isEDVUsed:         config.IsEDVUsed,
		authService:       config.AuthService,
		ldDocLoader:       config.LDDocumentLoader,
	}

	return op
}

// GetRESTHandlers gets handlers available for the hub-kms REST API.
func (o *Operation) GetRESTHandlers() []Handler {
	return []Handler{
		support.NewHTTPHandler(keystoresEndpoint, keystoresEndpoint, http.MethodPost, o.createKeystoreHandler),
		support.NewHTTPHandler(keysEndpoint, keysEndpoint, http.MethodPost, o.createKeyHandler),
		support.NewHTTPHandler(capabilityEndpoint, capabilityEndpoint, http.MethodPost, o.updateCapabilityHandler),
		support.NewHTTPHandler(exportEndpoint, exportEndpoint, http.MethodGet, o.exportKeyHandler),
		support.NewHTTPHandler(signEndpoint, signEndpoint, http.MethodPost, o.signHandler),
		support.NewHTTPHandler(verifyEndpoint, verifyEndpoint, http.MethodPost, o.verifyHandler),
		support.NewHTTPHandler(encryptEndpoint, encryptEndpoint, http.MethodPost, o.encryptHandler),
		support.NewHTTPHandler(decryptEndpoint, decryptEndpoint, http.MethodPost, o.decryptHandler),
		support.NewHTTPHandler(computeMACEndpoint, computeMACEndpoint, http.MethodPost, o.computeMACHandler),
		support.NewHTTPHandler(verifyMACEndpoint, verifyMACEndpoint, http.MethodPost, o.verifyMACHandler),
		support.NewHTTPHandler(wrapEndpoint, wrapEndpoint, http.MethodPost, o.wrapHandler),
		support.NewHTTPHandler(unwrapEndpoint, unwrapEndpoint, http.MethodPost, o.unwrapHandler),
	}
}

func (o *Operation) createKeystoreHandler(rw http.ResponseWriter, req *http.Request) {
	o.logger.Debugf("handling request: %s", req.URL.String())

	var request CreateKeystoreReq
	if ok := o.parseRequest(&request, rw, req); !ok {
		return
	}

	createdAt := time.Now().UTC()

	opts := []keystore.Option{
		keystore.WithID(xid.New().String()),
		keystore.WithController(request.Controller),
		keystore.WithDelegateKeyType(arieskms.ED25519Type),
		keystore.WithCreatedAt(&createdAt),
	}

	if o.isEDVUsed {
		opts = append(opts,
			keystore.WithRecipientKeyType(arieskms.ECDH256KWAES256GCM),
			keystore.WithMACKeyType(arieskms.HMACSHA256Tag256),
			keystore.WithVaultID(request.VaultID),
		)
	}

	k, err := o.keystoreService.Create(opts...)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusInternalServerError, createKeystoreFailure, err)

		return
	}

	didKey, err := o.authService.CreateDIDKey()
	if err != nil {
		o.writeErrorResponse(rw, http.StatusInternalServerError, createKeystoreFailure, err)

		return
	}

	resource := keystoreLocation(req.Host, k.ID)

	zcap, err := o.newCompressedZCAP(resource, k.Controller)
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

func (o *Operation) createKeyHandler(rw http.ResponseWriter, req *http.Request) {
	o.logger.Debugf("handling request: %s", req.URL.String())

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

	o.logger.Debugf("Location: %s", keyLocation(req.Host, keystoreID, keyID))
	o.logger.Debugf("finished handling request")
}

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

	ks, err := o.keystoreService.Get(keystoreID)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusInternalServerError, getKeystoreFailure, err)

		return
	}

	ks.EDVCapability = request.EDVCapability

	if err := o.keystoreService.Save(ks); err != nil {
		o.writeErrorResponse(rw, http.StatusInternalServerError, saveKeystoreFailure, err)

		return
	}

	rw.WriteHeader(http.StatusOK)
}

func (o *Operation) exportKeyHandler(rw http.ResponseWriter, req *http.Request) {
	o.logger.Debugf(prepareDebugOutputForRequest(req, o.logger))

	kmsService, err := o.kmsServiceCreator(req)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusInternalServerError, createKMSServiceFailure, err)

		return
	}

	keystoreID := mux.Vars(req)[keystoreIDQueryParam]
	keyID := mux.Vars(req)[keyIDQueryParam]

	bytes, err := kmsService.ExportKey(keystoreID, keyID)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusInternalServerError, exportKeyFailure, err)

		return
	}

	o.writeResponse(rw, exportKeyResp{
		PublicKey: base64.URLEncoding.EncodeToString(bytes),
	})
}

//nolint:dupl // better readability
func (o *Operation) signHandler(rw http.ResponseWriter, req *http.Request) {
	o.logger.Debugf("handling request: %s", req.URL.String())

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

	message, err := base64.URLEncoding.DecodeString(request.Message)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusBadRequest, receivedBadRequest, err)

		return
	}

	signature, err := kmsService.Sign(keystoreID, keyID, message)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusInternalServerError, signMessageFailure, err)

		return
	}

	o.writeResponse(rw, signResp{
		Signature: base64.URLEncoding.EncodeToString(signature),
	})

	o.logger.Debugf("finished handling request: %s", req.URL.String())
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

	message, err := base64.URLEncoding.DecodeString(request.Message)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusBadRequest, receivedBadRequest, err)

		return
	}

	err = kmsService.Verify(keystoreID, keyID, signature, message)
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

	cipherText, nonce, err := kmsService.Encrypt(keystoreID, keyID, message, aad)
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

	plainText, err := kmsService.Decrypt(keystoreID, keyID, cipherText, aad, nonce)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusInternalServerError, decryptMessageFailure, err)

		return
	}

	o.writeResponse(rw, decryptResp{
		PlainText: base64.URLEncoding.EncodeToString(plainText),
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

	data, err := base64.URLEncoding.DecodeString(request.Data)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusBadRequest, receivedBadRequest, err)

		return
	}

	mac, err := kmsService.ComputeMAC(keystoreID, keyID, data)
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

	data, err := base64.URLEncoding.DecodeString(request.Data)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusBadRequest, receivedBadRequest, err)

		return
	}

	err = kmsService.VerifyMAC(keystoreID, keyID, mac, data)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusInternalServerError, verifyMACFailure, err)

		return
	}

	rw.WriteHeader(http.StatusOK)
}

func (o *Operation) wrapHandler(rw http.ResponseWriter, req *http.Request) {
	kmsService, err := o.kmsServiceCreator(req)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusInternalServerError, createKMSServiceFailure, err)

		return
	}

	var request wrapReq
	if ok := o.parseRequest(&request, rw, req); !ok {
		return
	}

	keystoreID := mux.Vars(req)[keystoreIDQueryParam]

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

	wrappedKey, err := kmsService.WrapKey(keystoreID, request.SenderKID, cek, apu, apv, recPubKey)
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

//nolint:funlen // readability
func (o *Operation) unwrapHandler(rw http.ResponseWriter, req *http.Request) {
	kmsService, err := o.kmsServiceCreator(req)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusInternalServerError, createKMSServiceFailure, err)

		return
	}

	var request unwrapReq
	if ok := o.parseRequest(&request, rw, req); !ok {
		return
	}

	keystoreID := mux.Vars(req)[keystoreIDQueryParam]
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

	// TODO(#90): Implement support for Authcrypt unwrapping
	cek, err := kmsService.UnwrapKey(keystoreID, keyID, recipientWK, nil)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusInternalServerError, unwrapMessageFailure, err)

		return
	}

	o.writeResponse(rw, unwrapResp{Key: base64.URLEncoding.EncodeToString(cek)})
}

func (o *Operation) parseRequest(parsedReq interface{}, rw http.ResponseWriter, req *http.Request) bool {
	o.logger.Debugf(prepareDebugOutputForRequest(req, o.logger))

	if err := json.NewDecoder(req.Body).Decode(&parsedReq); err != nil {
		o.writeErrorResponse(rw, http.StatusBadRequest, receivedBadRequest, err)

		return false
	}

	return true
}

func prepareDebugOutputForRequest(
	req *http.Request, logger log.Logger) string { // nolint:interfacer // don't want to pull in test packages
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
		Message: fmt.Sprintf(messageFormat, kms.UserErrorMessage(err)),
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

func (o *Operation) newCompressedZCAP(resource, controller string) (string, error) {
	zcap, err := o.authService.NewCapability(
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
		return nil, err
	}

	x, err := base64.URLEncoding.DecodeString(k.X)
	if err != nil {
		return nil, err
	}

	y, err := base64.URLEncoding.DecodeString(k.Y)
	if err != nil {
		return nil, err
	}

	curve, err := base64.URLEncoding.DecodeString(k.Curve)
	if err != nil {
		return nil, err
	}

	typ, err := base64.URLEncoding.DecodeString(k.Type)
	if err != nil {
		return nil, err
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

func keystoreLocation(hostURL, keystoreID string) string {
	// {hostURL}/kms/keystores/{keystoreID}
	return fmt.Sprintf(
		"%s%s%s",
		hostURL,
		KMSBasePath,
		strings.ReplaceAll(keystoreEndpoint, "{keystoreID}", keystoreID),
	)
}

func keyLocation(hostURL, keystoreID, keyID string) string {
	// {hostURL}/kms/keystores/{keystoreID}/keys/{keyID}
	r := strings.NewReplacer(
		"{keystoreID}", keystoreID,
		"{keyID}", keyID)

	return fmt.Sprintf("%s%s%s", hostURL, KMSBasePath, r.Replace(keyEndpoint))
}

func allActions() []string {
	return []string{
		actionCreateKey,
		actionExportKey,
		actionSign,
		actionVerify,
		actionWrap,
		actionUnwrap,
		actionComputeMac,
		actionVerifyMAC,
		actionEncrypt,
		actionDecrypt,
		actionStoreCapability,
	}
}
