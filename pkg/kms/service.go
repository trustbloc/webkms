/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package kms

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/rs/xid"

	"github.com/trustbloc/kms/pkg/internal/support"
	"github.com/trustbloc/kms/pkg/keystore"
	lock "github.com/trustbloc/kms/pkg/secretlock"
	"github.com/trustbloc/kms/pkg/secretlock/secretsplitlock"
	"github.com/trustbloc/kms/pkg/storage/edv"
)

const (
	keystoreDB           = "keystoredb"
	primaryKeyURI        = "local-lock://%s"
	keystoreIDQueryParam = "keystoreID"
	secretHeader         = "Hub-Kms-Secret" //nolint:gosec // name of header with secret share
	userHeader           = "Hub-Kms-User"
)

// Config defines configuration for the KMS service.
type Config struct {
	StorageProvider           storage.Provider
	CacheProvider             storage.Provider
	KeyManagerStorageProvider storage.Provider

	LocalKMS      kms.KeyManager
	CryptoService crypto.Crypto
	HeaderSigner  edv.HeaderSigner

	PrimaryKeyStorageProvider storage.Provider
	PrimaryKeyLock            secretlock.Service
	CreateSecretLockFunc      func(keyURI string, provider lock.Provider) (secretlock.Service, error)

	EDVServerURL    string
	HubAuthURL      string
	HubAuthAPIToken string

	HTTPClient support.HTTPClient
	TLSConfig  *tls.Config
}

type service struct {
	store    storage.Store
	localKMS kms.KeyManager
	crypto   crypto.Crypto
	config   *Config
}

// NewService returns a new Service instance.
func NewService(c *Config) (Service, error) {
	store, err := c.StorageProvider.OpenStore(keystoreDB)
	if err != nil {
		return nil, fmt.Errorf("new service: %w", err)
	}

	return &service{
		store:    store,
		localKMS: c.LocalKMS,
		crypto:   c.CryptoService,
		config:   c,
	}, nil
}

// CreateKeystore creates a new Keystore.
func (s *service) CreateKeystore(controller, vaultID string) (*KeystoreData, error) {
	var recipientKeyID, macKeyID string

	if vaultID != "" {
		// TODO make default keystore's main key type configurable (for recKID only, macKID has fixed type)
		// TODO available types: NISTP256ECDHKW, NISTP384ECDHKW, NISTP521ECDHKW or X25519ECDHKW #154
		recKID, _, err := s.localKMS.Create(kms.NISTP256ECDHKW)
		if err != nil {
			return nil, fmt.Errorf("create keystore: %w", err)
		}

		recipientKeyID = recKID

		macKID, _, err := s.localKMS.Create(kms.HMACSHA256Tag256)
		if err != nil {
			return nil, fmt.Errorf("create keystore: %w", err)
		}

		macKeyID = macKID
	}

	createdAt := time.Now().UTC()

	keystoreData := &KeystoreData{
		ID:             xid.New().String(),
		Controller:     controller,
		RecipientKeyID: recipientKeyID,
		MACKeyID:       macKeyID,
		VaultID:        vaultID,
		CreatedAt:      &createdAt,
	}

	err := s.SaveKeystoreData(keystoreData)
	if err != nil {
		return nil, fmt.Errorf("create keystore: %w", err)
	}

	return keystoreData, nil
}

// ResolveKeystore resolves Keystore for the given request.
func (s *service) ResolveKeystore(req *http.Request) (keystore.Keystore, error) {
	keystoreID := mux.Vars(req)[keystoreIDQueryParam]

	keystoreData, err := s.GetKeystoreData(keystoreID)
	if err != nil {
		return nil, fmt.Errorf("resolve keystore: %w", err)
	}

	storageProvider := s.config.KeyManagerStorageProvider

	if s.config.EDVServerURL != "" {
		p, e := s.prepareEDVStorageProvider(req.Context(), keystoreData)
		if e != nil {
			return nil, fmt.Errorf("resolve keystore: %w", e)
		}

		storageProvider = p
	}

	primaryKeyLock := s.config.PrimaryKeyLock
	keyURI := fmt.Sprintf(primaryKeyURI, keystoreDB)

	if s.config.HubAuthURL != "" {
		l, e := s.prepareSecretSplitLock(req)
		if e != nil {
			return nil, fmt.Errorf("resolve keystore: %w", e)
		}

		primaryKeyLock = l
		keyURI = fmt.Sprintf(primaryKeyURI, keystoreID)
	}

	secLockProvider := &secretLockProvider{
		storageProvider: s.config.PrimaryKeyStorageProvider,
		secretLock:      primaryKeyLock,
	}

	secretLock, err := s.config.CreateSecretLockFunc(keyURI, secLockProvider)
	if err != nil {
		return nil, fmt.Errorf("resolve keystore: %w", err)
	}

	k, err := keystore.New(
		keystore.WithPrimaryKeyURI(keyURI),
		keystore.WithStorageProvider(storageProvider),
		keystore.WithSecretLock(secretLock),
	)
	if err != nil {
		return nil, fmt.Errorf("resolve keystore: %w", err)
	}

	return k, nil
}

func (s *service) prepareEDVStorageProvider(ctx context.Context, kd *KeystoreData) (storage.Provider, error) {
	edvConfig := &edv.Config{
		KeyManager:     s.localKMS,
		CryptoService:  s.config.CryptoService,
		HeaderSigner:   s.config.HeaderSigner,
		CacheProvider:  s.config.CacheProvider,
		TLSConfig:      s.config.TLSConfig,
		EDVServerURL:   s.config.EDVServerURL,
		EDVCapability:  kd.EDVCapability,
		VaultID:        kd.VaultID,
		RecipientKeyID: kd.RecipientKeyID,
		MACKeyID:       kd.MACKeyID,
	}

	return edv.NewStorageProvider(ctx, edvConfig)
}

func (s *service) prepareSecretSplitLock(req *http.Request) (secretlock.Service, error) {
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
		URL:      s.config.HubAuthURL,
		APIToken: s.config.HubAuthAPIToken,
		Subject:  sub,
	}

	return secretsplitlock.New(secretBytes, hubAuthParams,
		secretsplitlock.WithHTTPClient(s.config.HTTPClient),
		secretsplitlock.WithCacheProvider(s.config.CacheProvider),
	)
}

type secretLockProvider struct {
	storageProvider storage.Provider
	secretLock      secretlock.Service
}

func (p *secretLockProvider) StorageProvider() storage.Provider {
	return p.storageProvider
}

func (p *secretLockProvider) SecretLock() secretlock.Service {
	return p.secretLock
}

// GetKeystoreData retrieves Keystore metadata.
func (s *service) GetKeystoreData(keystoreID string) (*KeystoreData, error) {
	b, err := s.store.Get(keystoreID)
	if err != nil {
		return nil, err
	}

	var keystoreData KeystoreData

	err = json.Unmarshal(b, &keystoreData)
	if err != nil {
		return nil, err
	}

	return &keystoreData, nil
}

// SaveKeystoreData saves Keystore metadata.
func (s *service) SaveKeystoreData(keystoreData *KeystoreData) error {
	b, err := json.Marshal(keystoreData)
	if err != nil {
		return err
	}

	err = s.store.Put(keystoreData.ID, b)
	if err != nil {
		return err
	}

	return nil
}
