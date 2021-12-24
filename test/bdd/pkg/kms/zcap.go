/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package kms

import (
	"fmt"
	"net/http"

	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
)

const (
	edvResource     = "urn:edv:vault"
	edvDIDKeyHeader = "Edvdidkey"
)

const (
	actionCreateKey       = "createKey"
	actionExportKey       = "exportKey"
	actionImportKey       = "importKey"
	actionRotateKey       = "rotateKey"
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
)

type signer interface {
	// Sign will sign document and return signature.
	Sign(data []byte) ([]byte, error)
}

type authzKMSSigner struct {
	s         *Steps
	authzUser *user
}

func newAuthzKMSSigner(s *Steps, authzUser *user) *authzKMSSigner {
	return &authzKMSSigner{s: s, authzUser: authzUser}
}

func (a *authzKMSSigner) Sign(data []byte) ([]byte, error) {
	uri := a.s.bddContext.AuthZKeyServerURL + signEndpoint

	if err := a.s.makeSignMessageReqAuthzKMS(a.authzUser, uri, data); err != nil {
		return nil, err
	}

	return []byte(a.authzUser.data["signature"]), nil
}

type remoteKMS struct {
	keystoreID string
}

func (r *remoteKMS) Create(kt kms.KeyType) (string, interface{}, error) {
	panic("implement me")
}

func (r *remoteKMS) Get(keyID string) (interface{}, error) {
	return keyID, nil
}

func (r *remoteKMS) Rotate(kt kms.KeyType, keyID string) (string, interface{}, error) {
	panic("implement me")
}

func (r *remoteKMS) ExportPubKeyBytes(keyID string) ([]byte, error) {
	panic("implement me")
}

func (r *remoteKMS) CreateAndExportPubKeyBytes(kt kms.KeyType) (string, []byte, error) {
	panic("implement me")
}

func (r *remoteKMS) PubKeyBytesToHandle(pubKey []byte, kt kms.KeyType) (interface{}, error) {
	panic("implement me")
}

func (r *remoteKMS) ImportPrivateKey(
	privKey interface{}, kt kms.KeyType, opts ...kms.PrivateKeyOpts) (string, interface{}, error) {
	panic("implement me")
}

type remoteAuthCrypto struct {
	baseURL    string
	httpClient *http.Client
	user       *user
}

func (r *remoteAuthCrypto) Encrypt(msg, aad []byte, kh interface{}) ([]byte, []byte, error) {
	panic("implement me")
}

func (r *remoteAuthCrypto) Decrypt(cipher, aad, nonce []byte, kh interface{}) ([]byte, error) {
	panic("implement me")
}

func (r *remoteAuthCrypto) Sign(msg []byte, _ interface{}) ([]byte, error) {
	sig, err := r.user.signer.Sign(msg)
	if err != nil {
		return nil, fmt.Errorf("user's signer failed to sign: %w", err)
	}

	return sig, nil
}

func (r *remoteAuthCrypto) Verify(signature, msg []byte, kh interface{}) error {
	panic("implement me")
}

func (r *remoteAuthCrypto) ComputeMAC(data []byte, kh interface{}) ([]byte, error) {
	panic("implement me")
}

func (r *remoteAuthCrypto) VerifyMAC(mac, data []byte, kh interface{}) error {
	panic("implement me")
}

func (r *remoteAuthCrypto) WrapKey(cek, apu, apv []byte,
	recPubKey *crypto.PublicKey, opts ...crypto.WrapKeyOpts) (*crypto.RecipientWrappedKey, error) {
	panic("implement me")
}

func (r *remoteAuthCrypto) UnwrapKey(
	recWK *crypto.RecipientWrappedKey, kh interface{}, opts ...crypto.WrapKeyOpts) ([]byte, error) {
	panic("implement me")
}

func (r *remoteAuthCrypto) SignMulti(messages [][]byte, kh interface{}) ([]byte, error) {
	panic("implement me")
}

func (r *remoteAuthCrypto) VerifyMulti(messages [][]byte, signature []byte, kh interface{}) error {
	panic("implement me")
}

func (r *remoteAuthCrypto) DeriveProof(messages [][]byte, bbsSignature, nonce []byte, revealedIndexes []int,
	kh interface{}) ([]byte, error) {
	panic("implement me")
}

func (r *remoteAuthCrypto) VerifyProof(revealedMessages [][]byte, proof, nonce []byte, kh interface{}) error {
	panic("implement me")
}
