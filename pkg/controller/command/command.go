/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package command

//nolint:lll
//go:generate mockgen -destination gomocks_test.go -self_package mocks -package command_test -source=command.go -mock_names zcapService=MockZCAPService,headerSigner=MockHeaderSigner,keyStoreCreator=MockKeyStoreCreator,cryptoBoxCreator=MockCryptoBoxCreator,shamirSecretLockCreator=MockShamirSecretLockCreator,metricsProvider=MockMetricsProvider,cacheProvider=MockCacheProvider,shamirProvider=MockShamirProvider

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

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

// CryptoBox represents crypto box API.
type CryptoBox interface {
	Easy(payload, nonce, theirPub []byte, myKID string) ([]byte, error)
	EasyOpen(ciphertext, nonce, theirPub, myPub []byte) ([]byte, error)
	SealOpen(ciphertext, myPub []byte) ([]byte, error)
}

type cryptoBoxCreator interface {
	Create(km kms.KeyManager) (CryptoBox, error)
}

type shamirProvider interface {
	FetchSecretShare(subject string) ([]byte, error)
}

type shamirSecretLockCreator interface {
	Create(secretShares [][]byte) (secretlock.Service, error)
}

type metricsProvider interface {
	CryptoSignTime(value time.Duration)
	KeyStoreResolveTime(value time.Duration)
	KeyStoreGetKeyTime(value time.Duration)
}

type cacheProvider interface {
	Wrap(storageProvider storage.Provider, ttl time.Duration) storage.Provider
}

// Config is a configuration for Command.
type Config struct {
	StorageProvider         storage.Provider
	KeyStorageProvider      storage.Provider // storage provider for users' key stores
	KMS                     kms.KeyManager
	Crypto                  crypto.Crypto
	VDRResolver             zcapld.VDRResolver
	DocumentLoader          ld.DocumentLoader
	KeyStoreCreator         keyStoreCreator
	ShamirSecretLockCreator shamirSecretLockCreator
	CryptBoxCreator         cryptoBoxCreator
	ZCAPService             zcapService
	EnableZCAPs             bool
	HeaderSigner            headerSigner
	TLSConfig               *tls.Config
	BaseKeyStoreURL         string
	ShamirProvider          shamirProvider
	MainKeyType             kms.KeyType
	MetricsProvider         metricsProvider
	CacheProvider           cacheProvider
	KeyStoreCacheTTL        time.Duration
}

// Command is a controller for commands.
type Command struct {
	store              storage.Store
	keyStorageProvider storage.Provider
	kms                kms.KeyManager // server's key manager
	crypto             crypto.Crypto
	zcap               zcapService
	enableZCAPs        bool
	vdr                zcapld.VDRResolver
	documentLoader     ld.DocumentLoader
	keyStoreCreator    keyStoreCreator // user's key manager creator
	cryptoBox          cryptoBoxCreator
	shamirLock         shamirSecretLockCreator
	headerSigner       headerSigner
	tlsConfig          *tls.Config
	baseKeyStoreURL    string
	shamirProvider     shamirProvider
	mainKeyType        kms.KeyType
	cacheProvider      cacheProvider
	keyStoreCacheTTL   time.Duration
	metrics            metricsProvider
}

// New returns a new instance of Command.
func New(c *Config) (*Command, error) {
	store, err := c.StorageProvider.OpenStore(keyStores)
	if err != nil {
		return nil, fmt.Errorf("open key store db: %w", err)
	}

	return &Command{
		store:              store,
		keyStorageProvider: c.KeyStorageProvider,
		kms:                c.KMS,
		crypto:             c.Crypto,
		zcap:               c.ZCAPService,
		enableZCAPs:        c.EnableZCAPs,
		vdr:                c.VDRResolver,
		documentLoader:     c.DocumentLoader,
		keyStoreCreator:    c.KeyStoreCreator,
		shamirLock:         c.ShamirSecretLockCreator,
		cryptoBox:          c.CryptBoxCreator,
		headerSigner:       c.HeaderSigner,
		tlsConfig:          c.TLSConfig,
		baseKeyStoreURL:    c.BaseKeyStoreURL,
		shamirProvider:     c.ShamirProvider,
		mainKeyType:        c.MainKeyType,
		cacheProvider:      c.CacheProvider,
		keyStoreCacheTTL:   c.KeyStoreCacheTTL,
		metrics:            c.MetricsProvider,
	}, nil
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

	kid, _, err := ks.Create(req.KeyType, kms.WithAttrs(req.Attrs))
	if err != nil {
		return fmt.Errorf("create key: %w", err)
	}

	pub, _, err := ks.ExportPubKeyBytes(kid)
	if err != nil {
		if !strings.Contains(err.Error(), "failed to get public keyset handle") {
			return fmt.Errorf("export public key bytes: %w", err)
		}
	}

	return json.NewEncoder(w).Encode(CreateKeyResponse{
		KeyURL:    fmt.Sprintf("%s/%s/keys/%s", c.baseKeyStoreURL, wr.KeyStoreID, kid),
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

	b, kt, err := ks.ExportPubKeyBytes(wr.KeyID)
	if err != nil {
		return fmt.Errorf("export public key bytes: %w", err)
	}

	return json.NewEncoder(w).Encode(ExportKeyResponse{PublicKey: b, KeyType: string(kt)})
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
		return fmt.Errorf("not supported key type: %s", req.KeyType)
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
		KeyURL: fmt.Sprintf("%s/%s/keys/%s", c.baseKeyStoreURL, wr.KeyStoreID, kid),
	})
}

// RotateKey rotate key.
func (c *Command) RotateKey(w io.Writer, r io.Reader) error {
	var req RotateKeyRequest

	wr, err := unwrapRequest(&req, r)
	if err != nil {
		return fmt.Errorf("unwrap request: %w", err)
	}

	ks, err := c.resolveKeyStore(wr.KeyStoreID, wr.User, wr.SecretShare)
	if err != nil {
		return fmt.Errorf("resolve key store: %w", err)
	}

	kid, _, err := ks.Rotate(req.KeyType, wr.KeyID, kms.WithAttrs(req.Attrs))
	if err != nil {
		return fmt.Errorf("rotate key: %w", err)
	}

	return json.NewEncoder(w).Encode(RotateKeyResponse{
		KeyURL: fmt.Sprintf("%s/%s/keys/%s", c.baseKeyStoreURL, wr.KeyStoreID, kid),
	})
}

// Sign signs a message.
func (c *Command) Sign(w io.Writer, r io.Reader) error {
	var req SignRequest

	kh, err := c.getKeyHandle(&req, r)
	if err != nil {
		return err
	}

	signStartTime := time.Now()

	signature, err := c.crypto.Sign(req.Message, kh)
	if err != nil {
		return fmt.Errorf("sign: %w", err)
	}

	c.metrics.CryptoSignTime(time.Since(signStartTime))

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

// SignMulti creates a BBS+ signature of messages.
func (c *Command) SignMulti(w io.Writer, r io.Reader) error {
	var req SignMultiRequest

	kh, err := c.getKeyHandle(&req, r)
	if err != nil {
		return err
	}

	signature, err := c.crypto.SignMulti(req.Messages, kh)
	if err != nil {
		return fmt.Errorf("sign multi: %w", err)
	}

	return json.NewEncoder(w).Encode(SignMultiResponse{Signature: signature})
}

// VerifyMulti verifies a signature of messages (BBS+).
func (c *Command) VerifyMulti(_ io.Writer, r io.Reader) error {
	var req VerifyMultiRequest

	kh, err := c.getKeyHandle(&req, r)
	if err != nil {
		return err
	}

	if err = c.crypto.VerifyMulti(req.Messages, req.Signature, kh); err != nil {
		return fmt.Errorf("verify multi: %w", err)
	}

	return nil
}

// DeriveProof creates a BBS+ signature proof for a list of revealed messages.
func (c *Command) DeriveProof(w io.Writer, r io.Reader) error {
	var req DeriveProofRequest

	kh, err := c.getKeyHandle(&req, r)
	if err != nil {
		return err
	}

	proof, err := c.crypto.DeriveProof(req.Messages, req.Signature, req.Nonce, req.RevealedIndexes, kh)
	if err != nil {
		return fmt.Errorf("derive proof: %w", err)
	}

	return json.NewEncoder(w).Encode(DeriveProofResponse{Proof: proof})
}

// VerifyProof verifies a BBS+ signature proof for revealed messages.
func (c *Command) VerifyProof(_ io.Writer, r io.Reader) error {
	var req VerifyProofRequest

	kh, err := c.getKeyHandle(&req, r)
	if err != nil {
		return err
	}

	if err = c.crypto.VerifyProof(req.Messages, req.Proof, req.Nonce, kh); err != nil {
		return fmt.Errorf("verify proof: %w", err)
	}

	return nil
}

// easy seals a payload.
func (c *Command) easy(w io.Writer, wr *WrappedRequest, req *EasyRequest) error {
	cryptoBox, err := c.getCryptoBox(wr.KeyStoreID, wr.User, wr.SecretShare)
	if err != nil {
		return err
	}

	ciphertext, err := cryptoBox.Easy(req.Payload, req.Nonce, req.TheirPub, wr.KeyID)
	if err != nil {
		return fmt.Errorf("easy: %w", err)
	}

	return json.NewEncoder(w).Encode(EasyResponse{Ciphertext: ciphertext})
}

// easyOpen unseals a ciphertext sealed with Easy.
func (c *Command) easyOpen(w io.Writer, req *EasyOpenRequest, cryptoBox CryptoBox) error {
	plaintext, err := cryptoBox.EasyOpen(req.Ciphertext, req.Nonce, req.TheirPub, req.MyPub)
	if err != nil {
		return fmt.Errorf("easy open: %w", err)
	}

	return json.NewEncoder(w).Encode(EasyOpenResponse{Plaintext: plaintext})
}

// sealOpen decrypts a ciphertext encrypted with Seal.
func (c *Command) sealOpen(w io.Writer, req *SealOpenRequest, cryptoBox CryptoBox) error {
	plaintext, err := cryptoBox.SealOpen(req.Ciphertext, req.MyPub)
	if err != nil {
		return fmt.Errorf("seal open: %w", err)
	}

	return json.NewEncoder(w).Encode(SealOpenResponse{Plaintext: plaintext})
}

// WrapKey wraps a key.
func (c *Command) WrapKey(w io.Writer, r io.Reader) error {
	var req WrapKeyRequest

	wr, err := unwrapRequest(nil, r)
	if err != nil {
		return fmt.Errorf("unwrap wrap request: %w", err)
	}

	if err = json.Unmarshal(wr.Request, &req); err != nil {
		return fmt.Errorf("unmarshal unwrap wrap request: %w", err)
	}

	if req.CEK == nil {
		var reqEasy EasyRequest

		if err = json.Unmarshal(wr.Request, &reqEasy); err != nil {
			return fmt.Errorf("unmarshal unwrap wrap request: %w", err)
		}

		if err = c.easy(w, wr, &reqEasy); err != nil {
			return fmt.Errorf("unwrap wrap request: %w", err)
		}

		return nil
	}

	var opts []crypto.WrapKeyOpts

	if wr.KeyID != "" {
		ks, resolveErr := c.resolveKeyStore(wr.KeyStoreID, wr.User, wr.SecretShare)
		if resolveErr != nil {
			return fmt.Errorf("resolve key store: %w", resolveErr)
		}

		kh, getErr := ks.Get(wr.KeyID)
		if getErr != nil {
			return fmt.Errorf("get key %s: %w", wr.KeyID, getErr)
		}

		opts = append(opts, crypto.WithSender(kh))

		if req.Tag != nil {
			opts = append(opts, crypto.WithTag(req.Tag))
		}
	}

	wk, err := c.crypto.WrapKey(req.CEK, req.APU, req.APV, req.RecipientPubKey, opts...)
	if err != nil {
		return fmt.Errorf("wrap key: %w", err)
	}

	return json.NewEncoder(w).Encode(WrapKeyResponse{*wk})
}

// UnwrapKey unwraps a wrapped key.
func (c *Command) UnwrapKey(w io.Writer, r io.Reader) error {
	var req UnwrapKeyRequest

	wr, err := unwrapRequest(nil, r)
	if err != nil {
		return fmt.Errorf("unwrap request: %w", err)
	}

	if err = json.Unmarshal(wr.Request, &req); err != nil {
		return fmt.Errorf("unmarshal unwrapKey request: %w", err)
	}

	//nolint:nestif
	if req.WrappedKey.EncryptedCEK == nil && req.WrappedKey.Alg == "" {
		cryptoBox, e := c.getCryptoBox(wr.KeyStoreID, wr.User, wr.SecretShare)
		if e != nil {
			return fmt.Errorf("get cryptobox failed: %w", e)
		}

		var (
			eor EasyOpenRequest
			sor SealOpenRequest
		)

		if err = json.Unmarshal(wr.Request, &eor); err == nil && eor.Ciphertext != nil {
			if err = c.easyOpen(w, &eor, cryptoBox); err == nil {
				return nil
			}
		}

		if err = json.Unmarshal(wr.Request, &sor); err == nil {
			if err = c.sealOpen(w, &sor, cryptoBox); err == nil {
				return nil
			}
		}

		return fmt.Errorf("unwrapKey cryptobox request invalid: %w", err)
	}

	kh, err := c.getKeyHandleFromRequest(wr)
	if err != nil {
		return err
	}

	var opts []crypto.WrapKeyOpts

	if req.SenderPubKey != nil {
		opts = append(opts, crypto.WithSender(req.SenderPubKey))

		if req.Tag != nil {
			opts = append(opts, crypto.WithTag(req.Tag))
		}
	}

	k, err := c.crypto.UnwrapKey(&req.WrappedKey, kh, opts...)
	if err != nil {
		return fmt.Errorf("unwrap key: %w", err)
	}

	return json.NewEncoder(w).Encode(UnwrapKeyResponse{Key: k})
}

// Blind blinds values with CL MasterSecret key.
func (c *Command) Blind(w io.Writer, r io.Reader) error {
	var req BlindRequest

	kh, err := c.getKeyHandle(&req, r)
	if err != nil {
		return err
	}

	blinded, err := c.crypto.Blind(kh, req.Values...)
	if err != nil {
		return fmt.Errorf("blind: %w", err)
	}

	return json.NewEncoder(w).Encode(BlindResponse{Blinded: blinded})
}

// GetCorrectnessProof return correctness proof for a CL CredDef key.
func (c *Command) GetCorrectnessProof(w io.Writer, r io.Reader) error {
	kh, err := c.getKeyHandle(nil, r)
	if err != nil {
		return err
	}

	correctnessProof, err := c.crypto.GetCorrectnessProof(kh)
	if err != nil {
		return fmt.Errorf("get correctness proof: %w", err)
	}

	return json.NewEncoder(w).Encode(CorrectnessProofResponse{CorrectnessProof: correctnessProof})
}

// SignWithSecrets will generate a signature and a correctness proof
// for provided secrets and other values using a CL CredDef key.
func (c *Command) SignWithSecrets(w io.Writer, r io.Reader) error {
	var req SignWithSecretsRequest

	kh, err := c.getKeyHandle(&req, r)
	if err != nil {
		return err
	}

	signature, correctnessProof, err := c.crypto.SignWithSecrets(kh,
		req.Values,
		req.Secrets,
		req.CorrectnessProof,
		req.Nonces,
		req.DID,
	)
	if err != nil {
		return fmt.Errorf("sign with secrets: %w", err)
	}

	return json.NewEncoder(w).Encode(SignWithSecretsResponse{
		Signature:        signature,
		CorrectnessProof: correctnessProof,
	})
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

	getStartTime := time.Now()

	kh, err := ks.Get(wr.KeyID)
	if err != nil {
		return nil, fmt.Errorf("get key: %w", err)
	}

	c.metrics.KeyStoreGetKeyTime(time.Since(getStartTime))

	return kh, nil
}

func (c *Command) getKeyHandleFromRequest(wr *WrappedRequest) (interface{}, error) {
	ks, err := c.resolveKeyStore(wr.KeyStoreID, wr.User, wr.SecretShare)
	if err != nil {
		return nil, fmt.Errorf("resolve key store: %w", err)
	}

	getStartTime := time.Now()

	kh, err := ks.Get(wr.KeyID)
	if err != nil {
		return nil, fmt.Errorf("get key: %w", err)
	}

	c.metrics.KeyStoreGetKeyTime(time.Since(getStartTime))

	return kh, nil
}

func (c *Command) getCryptoBox(keyStoreID, user string, secretShare []byte) (CryptoBox, error) {
	ks, err := c.resolveKeyStore(keyStoreID, user, secretShare)
	if err != nil {
		return nil, fmt.Errorf("resolve key store: %w", err)
	}

	cryptoBox, err := c.cryptoBox.Create(ks)
	if err != nil {
		return nil, fmt.Errorf("create crypto box: %w", err)
	}

	return cryptoBox, nil
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
	startTime := time.Now()
	defer func() { c.metrics.KeyStoreResolveTime(time.Since(startTime)) }()

	b, err := c.store.Get(keyStoreID)
	if err != nil {
		return nil, fmt.Errorf("get key store meta: %w", err)
	}

	var meta keyStoreMeta

	if err = json.Unmarshal(b, &meta); err != nil {
		return nil, fmt.Errorf("unmarshal key store meta: %w", err)
	}

	storageProvider := c.getStorageProvider()

	var secretLock secretlock.Service

	if c.shamirProvider != nil {
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

	// TODO (#327): Create our own implementation of the KMS storage interface and pass it in here instead of wrapping
	//  the Aries storage provider.
	kmsStore, err := kms.NewAriesProviderWrapper(storageProvider)
	if err != nil {
		return nil, err
	}

	return c.keyStoreCreator.Create(localKeyURIPrefix+keyID, &keyStoreProvider{
		storageProvider: kmsStore,
		secretLock:      secretLock,
	})
}

func (c *Command) getStorageProvider() storage.Provider {
	storageProvider := c.keyStorageProvider

	if c.cacheProvider != nil && c.keyStoreCacheTTL > 0 {
		storageProvider = c.cacheProvider.Wrap(storageProvider, c.keyStoreCacheTTL)
	}

	return storageProvider
}
