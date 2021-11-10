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
	ariesstorage "github.com/hyperledger/aries-framework-go/spi/storage"
	tlsutil "github.com/trustbloc/edge-core/pkg/utils/tls"
)

// BDDContext is a global context shared between different test suites in bdd tests.
type BDDContext struct {
	KeyServerURL     string
	AuthKeyServerURL string
	EDVServerURL     string
	AuthServerURL string
	tlsConfig     *tls.Config
	KeyManager        kms.KeyManager
	Crypto            cryptoapi.Crypto
}

type kmsProvider struct {
	storageProvider   ariesstorage.Provider
	secretLockService secretlock.Service
}

func (k kmsProvider) StorageProvider() ariesstorage.Provider {
	return k.storageProvider
}

func (k kmsProvider) SecretLock() secretlock.Service {
	return k.secretLockService
}

// NewBDDContext creates a new BDD context.
func NewBDDContext(caCertPath string) (*BDDContext, error) {
	rootCAs, err := tlsutil.GetCertPool(false, []string{caCertPath})
	if err != nil {
		return nil, err
	}

	keyManager, err := localkms.New(
		"local-lock://custom-primary-key",
		kmsProvider{storageProvider: ariesmemstorage.NewProvider(), secretLockService: &noop.NoLock{}},
	)
	if err != nil {
		return nil, err
	}

	crypto, err := tinkcrypto.New()
	if err != nil {
		return nil, err
	}

	return &BDDContext{
		tlsConfig: &tls.Config{
			RootCAs: rootCAs, MinVersion: tls.VersionTLS12,
		},
		KeyManager: keyManager, Crypto: crypto,
	}, nil
}

// TLSConfig returns a TLS config that BDD context was initialized with.
func (ctx *BDDContext) TLSConfig() *tls.Config {
	return ctx.tlsConfig
}
