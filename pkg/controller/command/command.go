/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package command

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/google/tink/go/keyset"
	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/piprate/json-gold/ld"
	"github.com/trustbloc/edge-core/pkg/zcapld"

	"github.com/trustbloc/kms/pkg/controller/errors"
	"github.com/trustbloc/kms/pkg/secretlock/key"
)

type zcapService interface {
	CreateDIDKey(context.Context) (string, error)
	NewCapability(ctx context.Context, options ...zcapld.CapabilityOption) (*zcapld.Capability, error)
	KMS() kms.KeyManager
	Crypto() crypto.Crypto
	Resolve(string) (*zcapld.Capability, error)
}

// headerSigner computes a signature on the request and returns a header with the signature.
type headerSigner interface {
	SignHeader(*http.Request, []byte) (*http.Header, error)
}

type keyStoreCreator interface {
	Create(keyURI string, provider kms.Provider) (kms.KeyManager, error)
}

type httpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// Config is a configuration for Command.
type Config struct {
	StorageProvider     storage.Provider
	CacheProvider       storage.Provider
	KMS                 kms.KeyManager
	Crypto              crypto.Crypto
	VDRResolver         zcapld.VDRResolver
	DocumentLoader      ld.DocumentLoader
	KeyStoreCreator     keyStoreCreator
	ZCAPService         zcapService
	HeaderSigner        headerSigner
	HTTPClient          httpClient
	TLSConfig           *tls.Config
	BaseKeyStoreURL     string
	AuthServerURL       string
	AuthServerToken     string
	MainKeyType         kms.KeyType
	EDVRecipientKeyType kms.KeyType
	EDVMACKeyType       kms.KeyType
}

// Command is a controller for commands.
type Command struct {
	store               storage.Store
	storageProvider     storage.Provider
	kms                 kms.KeyManager // server's key manager
	crypto              crypto.Crypto
	zcap                zcapService
	vdr                 zcapld.VDRResolver
	documentLoader      ld.DocumentLoader
	keyStoreCreator     keyStoreCreator // user's key manager creator
	headerSigner        headerSigner
	httpClient          httpClient
	tlsConfig           *tls.Config
	baseKeyStoreURL     string
	authServerURL       string
	authServerToken     string
	mainKeyType         kms.KeyType
	edvRecipientKeyType kms.KeyType
	edvMACKeyType       kms.KeyType
}

// New returns a new instance of Command.
func New(c *Config) (*Command, error) {
	store, err := c.StorageProvider.OpenStore(keyStores)
	if err != nil {
		return nil, fmt.Errorf("open keystore db: %w", err)
	}

	return &Command{
		store:               store,
		storageProvider:     c.StorageProvider,
		kms:                 c.KMS,
		crypto:              c.Crypto,
		zcap:                c.ZCAPService,
		vdr:                 c.VDRResolver,
		documentLoader:      c.DocumentLoader,
		keyStoreCreator:     c.KeyStoreCreator,
		headerSigner:        c.HeaderSigner,
		httpClient:          c.HTTPClient,
		tlsConfig:           c.TLSConfig,
		baseKeyStoreURL:     c.BaseKeyStoreURL,
		authServerURL:       c.AuthServerURL,
		authServerToken:     c.AuthServerToken,
		mainKeyType:         c.MainKeyType,
		edvRecipientKeyType: c.EDVRecipientKeyType,
		edvMACKeyType:       c.EDVMACKeyType,
	}, nil
}

// CreateDID creates a new DID.
func (c *Command) CreateDID(w io.Writer, _ io.Reader) error {
	didKey, err := c.zcap.CreateDIDKey(context.Background())
	if err != nil {
		return fmt.Errorf("create did:key: %w", err)
	}

	return json.NewEncoder(w).Encode(CreateDIDResponse{DID: didKey})
}

// CreateKey creates a new key.
func (c *Command) CreateKey(w io.Writer, r io.Reader) error {
	var req CreateKeyRequest

	wr, err := unwrapRequest(&req, r)
	if err != nil {
		return fmt.Errorf("unwrap request: %w", err)
	}

	ks, err := c.resolveKeyStore(wr.KeyStoreID, wr.User, wr.SecretShare)
	if err != nil {
		return fmt.Errorf("resolve key store: %w", err)
	}

	kid, _, err := ks.Create(req.KeyType)
	if err != nil {
		return fmt.Errorf("create key: %w", err)
	}

	pub, err := ks.ExportPubKeyBytes(kid)
	if err != nil {
		if !strings.Contains(err.Error(), "failed to get public keyset handle") {
			return fmt.Errorf("export public key bytes: %w", err)
		}
	}

	return json.NewEncoder(w).Encode(CreateKeyResponse{
		KeyURL:    fmt.Sprintf("%s/%s/key/%s", c.baseKeyStoreURL, wr.KeyStoreID, kid),
		PublicKey: pub,
	})
}

// ExportKey exports a key.
func (c *Command) ExportKey(w io.Writer, r io.Reader) error {
	wr, err := unwrapRequest(nil, r)
	if err != nil {
		return fmt.Errorf("unwrap request: %w", err)
	}

	ks, err := c.resolveKeyStore(wr.KeyStoreID, wr.User, wr.SecretShare)
	if err != nil {
		return fmt.Errorf("resolve key store: %w", err)
	}

	b, err := ks.ExportPubKeyBytes(wr.KeyID)
	if err != nil {
		return fmt.Errorf("export public key bytes: %w", err)
	}

	return json.NewEncoder(w).Encode(ExportKeyResponse{PublicKey: b})
}

// ImportKey imports a key.
func (c *Command) ImportKey(w io.Writer, r io.Reader) error {
	var req ImportKeyRequest

	wr, err := unwrapRequest(&req, r)
	if err != nil {
		return fmt.Errorf("unwrap request: %w", err)
	}

	ks, err := c.resolveKeyStore(wr.KeyStoreID, wr.User, wr.SecretShare)
	if err != nil {
		return fmt.Errorf("resolve key store: %w", err)
	}

	var privateKey interface{}

	switch req.KeyType { //nolint:exhaustive
	case
		kms.ED25519Type,
		kms.ECDSAP256TypeDER,
		kms.ECDSAP384TypeDER,
		kms.ECDSAP521TypeDER,
		kms.ECDSAP256TypeIEEEP1363,
		kms.ECDSAP384TypeIEEEP1363,
		kms.ECDSAP521TypeIEEEP1363:
		privateKey, err = x509.ParsePKCS8PrivateKey(req.Key)
		if err != nil {
			return fmt.Errorf("parse private key: %w", err)
		}
	default:
		return fmt.Errorf("not supported key type %q", req.KeyType)
	}

	var opts []kms.PrivateKeyOpts

	if req.KeyID != "" {
		opts = append(opts, kms.WithKeyID(req.KeyID))
	}

	kid, _, err := ks.ImportPrivateKey(privateKey, req.KeyType, opts...)
	if err != nil {
		return fmt.Errorf("import private key: %w", err)
	}

	return json.NewEncoder(w).Encode(ImportKeyResponse{
		KeyURL: fmt.Sprintf("%s/%s/key/%s", c.baseKeyStoreURL, wr.KeyStoreID, kid),
	})
}

// Sign signs a message.
func (c *Command) Sign(w io.Writer, r io.Reader) error {
	var req SignRequest

	kh, err := c.getKeyHandle(&req, r)
	if err != nil {
		return err
	}

	signature, err := c.crypto.Sign(req.Message, kh)
	if err != nil {
		return fmt.Errorf("sign: %w", err)
	}

	return json.NewEncoder(w).Encode(SignResponse{Signature: signature})
}

// Verify verifies a signature.
func (c *Command) Verify(_ io.Writer, r io.Reader) error {
	var req VerifyRequest

	kh, err := c.getKeyHandle(&req, r)
	if err != nil {
		return err
	}

	pub, err := kh.(*keyset.Handle).Public()
	if err != nil {
		return fmt.Errorf("verify: %w", err)
	}

	if err = c.crypto.Verify(req.Signature, req.Message, pub); err != nil {
		return fmt.Errorf("verify: %w", err)
	}

	return nil
}

// Encrypt encrypts a message.
func (c *Command) Encrypt(w io.Writer, r io.Reader) error {
	var req EncryptRequest

	kh, err := c.getKeyHandle(&req, r)
	if err != nil {
		return err
	}

	cipher, nonce, err := c.crypto.Encrypt(req.Message, req.AssociatedData, kh)
	if err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}

	return json.NewEncoder(w).Encode(EncryptResponse{
		Ciphertext: cipher,
		Nonce:      nonce,
	})
}

// Decrypt decrypts a ciphertext.
func (c *Command) Decrypt(w io.Writer, r io.Reader) error {
	var req DecryptRequest

	kh, err := c.getKeyHandle(&req, r)
	if err != nil {
		return err
	}

	plain, err := c.crypto.Decrypt(req.Ciphertext, req.AssociatedData, req.Nonce, kh)
	if err != nil {
		return fmt.Errorf("decrypt: %w", err)
	}

	return json.NewEncoder(w).Encode(DecryptResponse{Plaintext: plain})
}

// ComputeMAC computes message authentication code for data.
func (c *Command) ComputeMAC(w io.Writer, r io.Reader) error {
	var req ComputeMACRequest

	kh, err := c.getKeyHandle(&req, r)
	if err != nil {
		return err
	}

	mac, err := c.crypto.ComputeMAC(req.Data, kh)
	if err != nil {
		return fmt.Errorf("compute mac: %w", err)
	}

	return json.NewEncoder(w).Encode(ComputeMACResponse{MAC: mac})
}

// VerifyMAC verifies message authentication code for data.
func (c *Command) VerifyMAC(_ io.Writer, r io.Reader) error {
	var req VerifyMACRequest

	kh, err := c.getKeyHandle(&req, r)
	if err != nil {
		return err
	}

	if err = c.crypto.VerifyMAC(req.MAC, req.Data, kh); err != nil {
		return fmt.Errorf("verify mac: %w", err)
	}

	return nil
}

func (c *Command) getKeyHandle(req interface{}, r io.Reader) (interface{}, error) {
	wr, err := unwrapRequest(req, r)
	if err != nil {
		return nil, fmt.Errorf("unwrap request: %w", err)
	}

	ks, err := c.resolveKeyStore(wr.KeyStoreID, wr.User, wr.SecretShare)
	if err != nil {
		return nil, fmt.Errorf("resolve key store: %w", err)
	}

	kh, err := ks.Get(wr.KeyID)
	if err != nil {
		return nil, fmt.Errorf("get key: %w", err)
	}

	return kh, nil
}

func unwrapRequest(req interface{}, r io.Reader) (*WrappedRequest, error) {
	var wr WrappedRequest

	if err := json.NewDecoder(r).Decode(&wr); err != nil {
		return nil, fmt.Errorf("%w: decode wrapped request", errors.ErrInternal)
	}

	if req != nil {
		if err := json.Unmarshal(wr.Request, req); err != nil {
			return nil, fmt.Errorf("%w: decode request", errors.ErrInternal)
		}
	}

	return &wr, nil
}

func (c *Command) resolveKeyStore(keyStoreID, user string, secretShare []byte) (kms.KeyManager, error) {
	b, err := c.store.Get(keyStoreID)
	if err != nil {
		return nil, fmt.Errorf("get key store meta: %w", err)
	}

	var meta keyStoreMeta

	if err = json.Unmarshal(b, &meta); err != nil {
		return nil, fmt.Errorf("unmarshal key store meta: %w", err)
	}

	var storageProvider storage.Provider

	if meta.EDV.VaultURL != "" {
		storageProvider, err = c.resolveEDVProvider(meta.EDV.VaultURL, meta.EDV.RecipientKeyID, meta.EDV.MACKeyID,
			meta.EDV.Capability)
		if err != nil {
			return nil, fmt.Errorf("resolve edv provider: %w", err)
		}
	} else {
		storageProvider = c.storageProvider
	}

	var secretLock secretlock.Service

	if c.authServerURL != "" {
		secretLock, err = c.createShamirSecretLock(user, secretShare)
		if err != nil {
			return nil, fmt.Errorf("create shamir secret lock: %w", err)
		}
	} else {
		secretLock = key.NewLock(&keyLockProvider{
			kms:    c.kms,
			crypto: c.crypto,
		})
	}

	keyID := meta.MainKeyID

	if keyID == "" {
		keyID = "noop"
	}

	return c.keyStoreCreator.Create(localKeyURIPrefix+keyID, &keyStoreProvider{
		storageProvider: storageProvider,
		secretLock:      secretLock,
	})
}

func (c *Command) resolveEDVProvider(vaultURL, recKeyID, macKeyID string, capability []byte) (storage.Provider, error) {
	recPubBytes, err := c.kms.ExportPubKeyBytes(recKeyID)
	if err != nil {
		return nil, fmt.Errorf("get edv recipient key: %w", err)
	}

	recPub := new(crypto.PublicKey)
	recPub.KID = recKeyID

	if err = json.Unmarshal(recPubBytes, recPub); err != nil {
		return nil, fmt.Errorf("unmarshal recipient key bytes to public key: %w", err)
	}

	macKH, err := c.kms.Get(macKeyID)
	if err != nil {
		return nil, fmt.Errorf("get edv mac key handle: %w", err)
	}

	edvProvider, err := c.createEDVStorageProvider(vaultURL, recPub, macKH, capability)
	if err != nil {
		return nil, fmt.Errorf("create edv provider: %w", err)
	}

	return edvProvider, nil
}
