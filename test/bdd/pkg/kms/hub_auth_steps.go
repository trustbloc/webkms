/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package kms

import (
	"encoding/base64"
	"fmt"

	"github.com/trustbloc/edge-core/pkg/sss/base"
	authlogin "github.com/trustbloc/hub-auth/test/bdd/pkg/login"

	"github.com/trustbloc/hub-kms/test/bdd/pkg/bddutil"
)

const (
	secretEndpoint = "/secret"
)

func (s *Steps) storeSecretInHubAuth(userName string) error {
	u, ok := s.users[userName]
	if !ok {
		u = &user{name: userName}

		s.users[userName] = u
	}

	secretA, secretB, err := createSecretShares()
	if err != nil {
		return err
	}

	u.secret = secretA

	login := authlogin.NewSteps(s.authBDDContext)

	wallet, err := login.NewWalletLogin()
	if err != nil {
		return err
	}

	u.subject = wallet.UserData.Sub

	r := setSecretRequest{
		Secret: secretB,
	}

	request, err := u.preparePostRequest(r, s.bddContext.HubAuthURL+secretEndpoint)
	if err != nil {
		return err
	}

	token := base64.StdEncoding.EncodeToString([]byte(s.authBDDContext.AccessToken()))

	request.Header.Set("authorization", fmt.Sprintf("Bearer %s", token))

	response, err := s.httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("http do: %w", err)
	}

	defer func() {
		closeErr := response.Body.Close()
		if closeErr != nil {
			s.logger.Errorf("Failed to close response body: %s\n", closeErr.Error())
		}
	}()

	return u.processResponse(nil, response)
}

func createSecretShares() ([]byte, []byte, error) {
	const splitParts = 2

	splitter := base.Splitter{}

	secrets, err := splitter.Split(bddutil.GenerateRandomBytes(), splitParts, splitParts)
	if err != nil {
		return nil, nil, err
	}

	return secrets[0], secrets[1], nil
}
