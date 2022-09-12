/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package kms

import (
	"fmt"
	kmsapi "github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/fingerprint"

	"github.com/trustbloc/kms/test/bdd/pkg/auth"
)

func (s *Steps) logIntoAuthServer(userName string) error {
	u := &user{
		name: userName,
	}
	s.users[userName] = u

	login := auth.NewAuthLogin(s.bddContext.LoginConfig, s.bddContext.TLSConfig())

	loggedWallet, accessToken, err := login.WalletLogin()
	if err != nil {
		return err
	}

	u.subject = loggedWallet.UserData.Sub
	u.accessToken = accessToken

	return nil
}

func (s *Steps) createProfileOnAuthServer(userName string) error {
	u := s.users[userName]

	authUser := &user{
		name:        userName,
		subject:     u.subject,
		accessToken: u.accessToken,
	}

	c, err := s.prepareAuthConfig(authUser)
	if err != nil {
		return err
	}

	u.controller = c
	u.signer = newZCAPAuthUserSigner(s, authUser)

	u.authKMS = s.bddContext.KeyManager
	u.authCrypto = s.bddContext.Crypto

	return nil
}

func (s *Steps) prepareAuthConfig(u *user) (string, error) {
	if errCreate := s.createKeyOnAuthKMS(u, "ED25519"); errCreate != nil {
		return "", fmt.Errorf("failed to create auth keystore key: %w", errCreate)
	}

	if errExport := s.exportPubKeyfromAuthKMS(u); errExport != nil {
		return "", fmt.Errorf("failed to export authz keystore key: %w", errExport)
	}

	pkBytes := []byte(u.data["publicKey"])

	_, didKey := fingerprint.CreateDIDKey(pkBytes)

	return didKey, nil
}

func (s *Steps) createKeyOnAuthKMS(u *user, keyType string) error {
	kid, _, err := s.bddContext.KeyManager.Create(kmsapi.KeyType(keyType))
	if err != nil {
		return err
	}
	u.keyID = kid

	return nil
}

func (s *Steps) exportPubKeyfromAuthKMS(u *user) error {
	bytes, _, err := s.bddContext.KeyManager.ExportPubKeyBytes(u.keyID)
	if err != nil {
		return err
	}

	u.data = map[string]string{
		"publicKey": string(bytes),
	}

	return nil
}
