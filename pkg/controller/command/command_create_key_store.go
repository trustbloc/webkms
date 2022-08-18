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
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"
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
	ID         string        `json:"id"`
	Controller string        `json:"controller"`
	MainKeyID  string        `json:"main_key_id"`
	EDV        edvParameters `json:"edv,omitempty"`
	CreatedAt  time.Time     `json:"created_at"`
}

type edvParameters struct {
	VaultURL       string `json:"vault_url"`
	RecipientKeyID string `json:"recipient_key_id"`
	MACKeyID       string `json:"mac_key_id"`
	Capability     []byte `json:"capability"`
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

	kmsStore, edvParams, err := c.createKMSStore(&req)
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
		EDV:        edvParams,
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

func (c *Command) createKMSStore(req *CreateKeyStoreRequest) (kms.Store, edvParameters, error) {
	var (
		edvParams       edvParameters
		storageProvider storage.Provider
		err             error
	)

	if req.EDV != nil { // use EDV for storing user's operational keys
		storageProvider, edvParams, err = c.prepareEDVProvider(req.EDV.VaultURL, req.EDV.Capability)
		if err != nil {
			return nil, edvParameters{}, fmt.Errorf("prepare edv provider: %w", err)
		}
	} else {
		storageProvider = c.keyStorageProvider
	}

	if c.cacheProvider != nil && c.keyStoreCacheTTL > 0 {
		storageProvider = c.cacheProvider.Wrap(storageProvider, c.keyStoreCacheTTL)
	}

	// TODO (#327): Create our own implementation of the KMS storage interface and pass it in here instead of wrapping
	//  the Aries storage provider.
	kmsStore, err := kms.NewAriesProviderWrapper(storageProvider)
	if err != nil {
		return nil, edvParameters{}, err
	}

	return kmsStore, edvParams, nil
}

func (c *Command) prepareEDVProvider(vaultURL string, capability []byte) (storage.Provider, edvParameters, error) {
	recKID, pub, err := c.createRecipientKey()
	if err != nil {
		return nil, edvParameters{}, fmt.Errorf("create edv recipient key: %w", err)
	}

	macKID, kh, err := c.createMACKey()
	if err != nil {
		return nil, edvParameters{}, fmt.Errorf("create edv mac key: %w", err)
	}

	edvParams := edvParameters{
		VaultURL:       vaultURL,
		RecipientKeyID: recKID,
		MACKeyID:       macKID,
		Capability:     capability,
	}

	edvProvider, err := c.createEDVStorageProvider(edvParams.VaultURL, pub, kh, edvParams.Capability)
	if err != nil {
		return nil, edvParameters{}, fmt.Errorf("create edv provider: %w", err)
	}

	return edvProvider, edvParams, nil
}

func (c *Command) createRecipientKey() (string, *crypto.PublicKey, error) {
	kid, b, err := c.kms.CreateAndExportPubKeyBytes(c.edvRecipientKeyType)
	if err != nil {
		return "", nil, fmt.Errorf("create key: %w", err)
	}

	pub := new(crypto.PublicKey)
	pub.KID = kid

	err = json.Unmarshal(b, pub)
	if err != nil {
		return "", nil, fmt.Errorf("unmarshal key bytes to public key: %w", err)
	}

	return kid, pub, nil
}

func (c *Command) createMACKey() (string, interface{}, error) {
	kid, kh, err := c.kms.Create(c.edvMACKeyType)
	if err != nil {
		return "", nil, fmt.Errorf("create key: %w", err)
	}

	return kid, kh, nil
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

const (
	encAlg  = jose.A256GCM
	encType = "EDVEncryptedDocument"
)

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
