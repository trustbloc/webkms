/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package startcmd

import (
	"crypto/tls"
	"net/http"
	"strings"
	"time"

	cryptoapi "github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock"
	ariesstorage "github.com/hyperledger/aries-framework-go/pkg/storage"
	tlsutils "github.com/trustbloc/edge-core/pkg/utils/tls"

	"github.com/trustbloc/hub-kms/pkg/keystore"
	"github.com/trustbloc/hub-kms/pkg/kms"
	"github.com/trustbloc/hub-kms/pkg/storage/cache"
	"github.com/trustbloc/hub-kms/pkg/storage/edv"
)

func prepareKMSServiceCreator(keystoreSrv keystore.Service, cryptoSrv cryptoapi.Crypto, signer edv.HeaderSigner,
	primaryKeyStorage ariesstorage.Provider, params *kmsRestParameters) (kms.ServiceCreator, error) {
	rootCAs, err := tlsutils.GetCertPool(params.tlsUseSystemCertPool, params.tlsCACerts)
	if err != nil {
		return nil, err
	}

	tlsConfig := &tls.Config{
		RootCAs:    rootCAs,
		MinVersion: tls.VersionTLS12,
	}

	var cacheProvider ariesstorage.Provider

	if params.cacheExpiration != "" {
		exp, err := time.ParseDuration(params.cacheExpiration)
		if err != nil {
			return nil, err
		}

		cacheProvider = cache.NewProvider(cache.WithExpiration(exp))
	}

	storageResolver := prepareStorageResolver(keystoreSrv, cryptoSrv, signer, cacheProvider,
		params.keyManagerStorageParams, tlsConfig)

	return kms.NewServiceCreator(&kms.Config{
		KeystoreService:    keystoreSrv,
		CryptoService:      cryptoSrv,
		KMSStorageResolver: storageResolver,
		SecretLockResolver: prepareSecretLockResolver(params, primaryKeyStorage, tlsConfig),
	}), nil
}

func prepareStorageResolver(keystoreSrv keystore.Service, cryptoSrv cryptoapi.Crypto, signer edv.HeaderSigner,
	cacheProvider ariesstorage.Provider, storageParams *storageParameters,
	tlsConfig *tls.Config) func(string) (ariesstorage.Provider, error) {
	switch {
	case strings.EqualFold(storageParams.storageType, storageTypeEDVOption):
		return func(keystoreID string) (ariesstorage.Provider, error) {
			config := &edv.Config{
				KeystoreService: keystoreSrv,
				CryptoService:   cryptoSrv,
				HeaderSigner:    signer,
				EDVServerURL:    storageParams.storageURL,
				KeystoreID:      keystoreID,
				TLSConfig:       tlsConfig,
				CacheProvider:   cacheProvider,
			}

			return edv.NewStorageProvider(config)
		}
	default:
		return func(string) (ariesstorage.Provider, error) {
			return prepareKMSStorageProvider(storageParams)
		}
	}
}

func prepareSecretLockResolver(params *kmsRestParameters, primaryKeyStorage ariesstorage.Provider,
	tlsConfig *tls.Config) func(keyURI string, req *http.Request) (secretlock.Service, error) {
	switch {
	case params.hubAuthURL != "":
		return func(keyURI string, req *http.Request) (secretlock.Service, error) {
			return prepareSecretSplitLock(primaryKeyStorage, req, tlsConfig, keyURI,
				params.hubAuthURL, params.hubAuthAPIToken)
		}
	default:
		return func(string, *http.Request) (secretlock.Service, error) {
			return preparePrimaryKeyLock(primaryKeyStorage, params.secretLockKeyPath)
		}
	}
}
