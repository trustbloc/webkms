/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package command

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/rs/xid"
	"github.com/trustbloc/edge-core/pkg/zcapld"

	"github.com/trustbloc/kms/pkg/controller/errors"
	"github.com/trustbloc/kms/pkg/secretlock/key"
	zcapldsvc "github.com/trustbloc/kms/pkg/zcapld"
)

const (
	keyStores         = "keystores"
	localKeyURIPrefix = "local-lock://"
)

// keyStoreMeta is metadata about user's key store saved in the underlying storage.
type keyStoreMeta struct {
	ID         string    `json:"id"`
	Controller string    `json:"controller"`
	MainKeyID  string    `json:"main_key_id"`
	CreatedAt  time.Time `json:"created_at"`
}

// CreateKeyStore creates a new key store.
func (c *Command) CreateKeyStore(w io.Writer, r io.Reader) error { //nolint:funlen
	var req CreateKeyStoreRequest

	wr, err := unwrapRequest(&req, r)
	if err != nil {
		return fmt.Errorf("unwrap request: %w", err)
	}

	if err = req.Validate(); err != nil {
		return fmt.Errorf("validate request: %w", err)
	}

	kmsStore, err := c.createKMSStore()
	if err != nil {
		return err
	}

	var secretLock secretlock.Service

	var mainKeyID string

	if c.shamirProvider != nil { // shamir secret sharing lock
		secretLock, err = c.createShamirSecretLock(wr.User, wr.SecretShare)
		if err != nil {
			return fmt.Errorf("create shamir secret lock: %w", err)
		}
	} else { // key-based secret lock
		mainKeyID, _, err = c.kms.Create(c.mainKeyType)
		if err != nil {
			return fmt.Errorf("create main key: %w", err)
		}

		secretLock = key.NewLock(&keyLockProvider{
			kms:    c.kms,
			crypto: c.crypto,
		})
	}

	meta := &keyStoreMeta{
		ID:         xid.New().String(),
		Controller: req.Controller,
		MainKeyID:  mainKeyID,
		CreatedAt:  time.Now().UTC(),
	}

	if mainKeyID == "" {
		mainKeyID = "noop"
	}

	_, err = c.keyStoreCreator.Create(localKeyURIPrefix+mainKeyID, &keyStoreProvider{
		storageProvider: kmsStore,
		secretLock:      secretLock,
	})
	if err != nil {
		return fmt.Errorf("create key store: %w", err)
	}

	keyStoreURL := c.baseKeyStoreURL + "/" + meta.ID

	var rootCapability []byte

	if c.enableZCAPs {
		rootCapability, err = c.newCompressedZCAP(context.Background(), keyStoreURL, req.Controller)
		if err != nil {
			return fmt.Errorf("new compressed zcap: %w", err)
		}
	}

	if err = c.save(meta); err != nil {
		return fmt.Errorf("save key store metadata: %w", err)
	}

	return json.NewEncoder(w).Encode(CreateKeyStoreResponse{
		KeyStoreURL: keyStoreURL,
		Capability:  rootCapability,
	})
}

func (c *Command) createKMSStore() (kms.Store, error) {
	var (
		storageProvider storage.Provider
		err             error
	)

	storageProvider = c.keyStorageProvider
	if c.cacheProvider != nil && c.keyStoreCacheTTL > 0 {
		storageProvider = c.cacheProvider.Wrap(storageProvider, c.keyStoreCacheTTL)
	}

	// TODO (#327): Create our own implementation of the KMS storage interface and pass it in here instead of wrapping
	//  the Aries storage provider.
	kmsStore, err := kms.NewAriesProviderWrapper(storageProvider)
	if err != nil {
		return nil, err
	}

	return kmsStore, nil
}

func (c *Command) newCompressedZCAP(ctx context.Context, resource, controller string) ([]byte, error) {
	capability, err := c.zcap.NewCapability(ctx,
		zcapld.WithInvocationTarget(resource, "urn:kms:keystore"),
		zcapld.WithInvoker(controller),
		zcapld.WithID(resource),
		zcapld.WithAllowedActions(allActions()...),
	)
	if err != nil {
		return nil, fmt.Errorf("create zcap: %w", err)
	}

	compressed, err := zcapldsvc.CompressZCAP(capability)
	if err != nil {
		return nil, fmt.Errorf("compress zcap: %w", err)
	}

	return compressed, nil
}

func (c *Command) createShamirSecretLock(user string, secretShare []byte) (secretlock.Service, error) {
	if user == "" {
		return nil, fmt.Errorf("%w: empty user", errors.ErrValidation)
	}

	if secretShare == nil {
		return nil, fmt.Errorf("%w: empty secret share", errors.ErrValidation)
	}

	share, err := c.shamirProvider.FetchSecretShare(user) // secret share from Auth server
	if err != nil {
		return nil, fmt.Errorf("fetch secret share: %w", err)
	}

	secretLock, err := c.shamirLock.Create([][]byte{secretShare, share})
	if err != nil {
		return nil, fmt.Errorf("create shamir lock: %w", err)
	}

	return secretLock, nil
}

func (c *Command) save(meta *keyStoreMeta) error {
	b, err := json.Marshal(meta)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	err = c.store.Put(meta.ID, b)
	if err != nil {
		return fmt.Errorf("put: %w", err)
	}

	return nil
}

type keyStoreProvider struct {
	storageProvider kms.Store
	secretLock      secretlock.Service
}

func (p *keyStoreProvider) StorageProvider() kms.Store {
	return p.storageProvider
}

func (p *keyStoreProvider) SecretLock() secretlock.Service {
	return p.secretLock
}

type keyLockProvider struct {
	kms    kms.KeyManager
	crypto crypto.Crypto
}

func (p *keyLockProvider) KMS() kms.KeyManager {
	return p.kms
}

func (p *keyLockProvider) Crypto() crypto.Crypto {
	return p.crypto
}
