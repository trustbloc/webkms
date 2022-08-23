/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package context

import (
	"crypto/tls"

	ariesmemstorage "github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	cryptoapi "github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/localkms"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock/noop"
	tlsutils "github.com/trustbloc/edge-core/pkg/utils/tls"

	"github.com/trustbloc/kms/test/bdd/pkg/auth"
)

// BDDContext is a global context shared between different test suites in bdd tests.
type BDDContext struct {
	KeyServerURL      string
	AuthZKeyServerURL string
	EDVServerURL      string
	HubAuthURL        string
	LoginConfig       *auth.LoginConfig
	tlsConfig         *tls.Config
	KeyManager        kms.KeyManager
	Crypto            cryptoapi.Crypto
}

type kmsProvider struct {
	storageProvider   kms.Store
	secretLockService secretlock.Service
}

func (k kmsProvider) StorageProvider() kms.Store {
	return k.storageProvider
}

func (k kmsProvider) SecretLock() secretlock.Service {
	return k.secretLockService
}

// NewBDDContext creates a new BDD context.
func NewBDDContext(caCertPath string) (*BDDContext, error) {
	var tlsConfig *tls.Config

	if caCertPath != "" {
		rootCAs, err := tlsutils.GetCertPool(false, []string{caCertPath})
		if err != nil {
			return nil, err
		}

		tlsConfig = &tls.Config{
			RootCAs: rootCAs, MinVersion: tls.VersionTLS12,
		}
	}

	kmsStore, err := kms.NewAriesProviderWrapper(ariesmemstorage.NewProvider())
	if err != nil {
		return nil, err
	}

	keyManager, err := localkms.New(
		"local-lock://custom-primary-key",
		kmsProvider{storageProvider: kmsStore, secretLockService: &noop.NoLock{}},
	)
	if err != nil {
		return nil, err
	}

	crypto, err := tinkcrypto.New()
	if err != nil {
		return nil, err
	}

	return &BDDContext{
		tlsConfig:  tlsConfig,
		KeyManager: keyManager, Crypto: crypto,
	}, nil
}

// TLSConfig returns a TLS config that BDD context was initialized with.
func (ctx *BDDContext) TLSConfig() *tls.Config {
	return ctx.tlsConfig
}
