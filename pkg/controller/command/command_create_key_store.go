/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package command

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/hyperledger/aries-framework-go/component/storage/edv"
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

	var (
		mainKeyID       string
		edvParams       edvParameters
		storageProvider storage.Provider
	)

	if req.EDV != nil { // use EDV for storing user's operational keys
		storageProvider, edvParams, err = c.prepareEDVProvider(req.EDV.VaultURL, req.EDV.Capability)
		if err != nil {
			return fmt.Errorf("prepare edv provider: %w", err)
		}
	} else {
		storageProvider = c.keyStorageProvider
	}

	if c.cacheProvider != nil && c.keyStoreCacheTTL > 0 {
		storageProvider = c.cacheProvider.Wrap(storageProvider, c.keyStoreCacheTTL)
	}

	var secretLock secretlock.Service

	if c.authServerURL != "" { // shamir secret sharing lock
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
		storageProvider: storageProvider,
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

func (c *Command) createEDVStorageProvider(vaultURL string, recipientPubKey *crypto.PublicKey,
	macKeyHandle interface{}, capability []byte) (storage.Provider, error) {
	jweEncrypt, err := jose.NewJWEEncrypt(encAlg, encType, "", "", nil, []*crypto.PublicKey{recipientPubKey}, c.crypto)
	if err != nil {
		return nil, fmt.Errorf("create jwe encrypt: %w", err)
	}

	jweDecrypt := jose.NewJWEDecrypt(nil, c.crypto, c.kms)

	encryptedFormatter := edv.NewEncryptedFormatter(
		jweEncrypt,
		jweDecrypt,
		edv.NewMACCrypto(macKeyHandle, c.crypto),
		edv.WithDeterministicDocumentIDs(),
	)

	s := strings.Split(vaultURL, "/")

	edvServerURL := strings.Join(s[:len(s)-1], "/")
	vaultID := s[len(s)-1]

	return edv.NewRESTProvider(
		edvServerURL,
		vaultID,
		encryptedFormatter,
		edv.WithTLSConfig(c.tlsConfig),
		edv.WithHeaders(func(req *http.Request) (*http.Header, error) {
			return c.headerSigner.SignHeader(req, capability)
		}),
	), nil
}

func (c *Command) createShamirSecretLock(user string, secretShare []byte) (secretlock.Service, error) {
	if user == "" {
		return nil, fmt.Errorf("%w: empty user", errors.ErrValidation)
	}

	if secretShare == nil {
		return nil, fmt.Errorf("%w: empty secret share", errors.ErrValidation)
	}

	share, err := c.fetchSecretShare(user) // secret share from Auth server
	if err != nil {
		return nil, fmt.Errorf("fetch secret share: %w", err)
	}

	secretLock, err := c.shamirLock.Create([][]byte{secretShare, share})
	if err != nil {
		return nil, fmt.Errorf("create shamir lock: %w", err)
	}

	return secretLock, nil
}

func (c *Command) fetchSecretShare(sub string) ([]byte, error) {
	uri := fmt.Sprintf("%s/secret?sub=%s", c.authServerURL, url.QueryEscape(sub))

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, uri, nil)
	if err != nil {
		return nil, fmt.Errorf("new request: %w", err)
	}

	req.Header.Set("authorization",
		fmt.Sprintf("Bearer %s", base64.StdEncoding.EncodeToString([]byte(c.authServerToken))),
	)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http do: %w", err)
	}

	defer resp.Body.Close() // nolint: errcheck

	if resp.StatusCode != http.StatusOK {
		return nil, getError(resp.Body)
	}

	var body struct {
		Secret string `json:"secret"`
	}

	if err = json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("decode response body: %w", err)
	}

	secret, err := base64.StdEncoding.DecodeString(body.Secret)
	if err != nil {
		return nil, fmt.Errorf("decode secret: %w", err)
	}

	return secret, nil
}

func getError(reader io.Reader) error {
	body, er := io.ReadAll(reader)
	if er != nil {
		return fmt.Errorf("read body: %w", er)
	}

	var errMsg struct {
		Message string `json:"message"`
	}

	if err := json.Unmarshal(body, &errMsg); err != nil {
		return errors.New(string(body))
	}

	return errors.New(errMsg.Message)
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
	storageProvider storage.Provider
	secretLock      secretlock.Service
}

func (p *keyStoreProvider) StorageProvider() storage.Provider {
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
