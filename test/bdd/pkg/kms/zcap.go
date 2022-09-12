/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package kms

const (
	actionCreateKey  = "createKey"
	actionExportKey  = "exportKey"
	actionImportKey  = "importKey"
	actionRotateKey  = "rotateKey"
	actionSign       = "sign"
	actionVerify     = "verify"
	actionWrap       = "wrap"
	actionUnwrap     = "unwrap"
	actionComputeMac = "computeMAC"
	actionVerifyMAC  = "verifyMAC"
	actionEncrypt    = "encrypt"
	actionDecrypt    = "decrypt"
)

type signer interface {
	// Sign will sign document and return signature.
	Sign(data []byte) ([]byte, error)
	Alg() string
}

type zcapAuthUserSigner struct {
	s         *Steps
	authzUser *user
}

func newZCAPAuthUserSigner(s *Steps, authzUser *user) *zcapAuthUserSigner {
	return &zcapAuthUserSigner{s: s, authzUser: authzUser}
}

func (a *zcapAuthUserSigner) Sign(data []byte) ([]byte, error) {
	kh, err := a.s.bddContext.KeyManager.Get(a.authzUser.keyID)
	if err != nil {
		return nil, err
	}

	s, err := a.s.bddContext.Crypto.Sign(data, kh)
	if err != nil {
		return nil, err
	}
	a.authzUser.data = map[string]string{
		"signature": string(s),
	}

	return []byte(a.authzUser.data["signature"]), nil
}

func (a *zcapAuthUserSigner) Alg() string {
	return ""
}
