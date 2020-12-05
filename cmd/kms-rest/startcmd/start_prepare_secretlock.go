/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package startcmd

import (
	"crypto/tls"
	"encoding/base64"
	"errors"
	"net/http"

	"github.com/hyperledger/aries-framework-go/pkg/secretlock"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock/local"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock/noop"
	ariesstorage "github.com/hyperledger/aries-framework-go/pkg/storage"

	lock "github.com/trustbloc/hub-kms/pkg/secretlock"
	"github.com/trustbloc/hub-kms/pkg/secretlock/secretsplitlock"
)

const (
	secretHeader = "Hub-Kms-Secret" //nolint:gosec // name of header with secret share
	userHeader   = "Hub-Kms-User"
)

func preparePrimaryKeyLock(primaryKeyStorage ariesstorage.Provider, keyPath string) (secretlock.Service, error) {
	if keyPath == "" {
		return &noop.NoLock{}, nil
	}

	primaryKeyReader, err := local.MasterKeyFromPath(keyPath)
	if err != nil {
		return nil, err
	}

	secLock, err := local.NewService(primaryKeyReader, nil)
	if err != nil {
		return nil, err
	}

	secLockProvider := &secretLockProvider{
		storageProvider: primaryKeyStorage,
		secretLock:      secLock,
	}

	secretLock, err := lock.New(keystorePrimaryKeyURI, secLockProvider)
	if err != nil {
		return nil, err
	}

	return secretLock, nil
}

func prepareSecretSplitLock(primaryKeyStorage ariesstorage.Provider, req *http.Request, tlsConfig *tls.Config,
	cacheProvider ariesstorage.Provider, keyURI, hubAuthURL, hubAuthAPIToken string) (secretlock.Service, error) {
	secret := req.Header.Get(secretHeader)
	if secret == "" {
		return nil, errors.New("empty secret share in the header")
	}

	secretBytes, err := base64.StdEncoding.DecodeString(secret)
	if err != nil {
		return nil, errors.New("fail to decode secret share from the header")
	}

	sub := req.Header.Get(userHeader)
	if sub == "" {
		return nil, errors.New("empty user in the header")
	}

	hubAuthParams := &secretsplitlock.HubAuthParams{
		URL:      hubAuthURL,
		APIToken: hubAuthAPIToken,
		Subject:  sub,
	}

	secLock, err := secretsplitlock.New(secretBytes, hubAuthParams,
		secretsplitlock.WithHTTPClient(&http.Client{
			Transport: &http.Transport{
				TLSClientConfig: tlsConfig,
			},
		}),
		secretsplitlock.WithCacheProvider(cacheProvider),
	)
	if err != nil {
		return nil, err
	}

	secLockProvider := &secretLockProvider{
		storageProvider: primaryKeyStorage,
		secretLock:      secLock,
	}

	secretLock, err := lock.New(keyURI, secLockProvider)
	if err != nil {
		return nil, err
	}

	return secretLock, nil
}

type secretLockProvider struct {
	storageProvider ariesstorage.Provider
	secretLock      secretlock.Service
}

func (p *secretLockProvider) StorageProvider() ariesstorage.Provider {
	return p.storageProvider
}

func (p *secretLockProvider) SecretLock() secretlock.Service {
	return p.secretLock
}
