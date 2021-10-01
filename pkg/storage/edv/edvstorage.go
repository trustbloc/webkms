/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package edv

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/google/tink/go/keyset"
	"github.com/hyperledger/aries-framework-go/component/storage/edv"
	"github.com/hyperledger/aries-framework-go/component/storageutil/cachedstore"
	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite/keyio"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/spi/storage"
)

const (
	edvEndpointPathRoot = "/encrypted-data-vaults"
)

const (
	encAlg  = jose.A256GCM
	encType = "EDVEncryptedDocument"
)

// HeaderSigner computes a signature on the request and returns a header with the signature.
type HeaderSigner interface {
	SignHeader(*http.Request, []byte) (*http.Header, error)
}

// Config defines configuration for the EDV storage provider.
type Config struct {
	KeyManager     kms.KeyManager
	CryptoService  crypto.Crypto
	HeaderSigner   HeaderSigner
	CacheProvider  storage.Provider
	TLSConfig      *tls.Config
	EDVCapability  json.RawMessage
	EDVServerURL   string
	VaultID        string
	RecipientKeyID string
	MACKeyID       string
}

// NewStorageProvider returns a new EDV storage provider instance.
func NewStorageProvider(c *Config) (storage.Provider, error) {
	macKH, err := c.KeyManager.Get(c.MACKeyID)
	if err != nil {
		return nil, fmt.Errorf("get mac key handle: %w", err)
	}

	macCrypto := edv.NewMACCrypto(macKH, c.CryptoService)

	encryptedFormatter, err := c.createEncryptedFormatter(macCrypto)
	if err != nil {
		return nil, err
	}

	restProvider := edv.NewRESTProvider(
		c.EDVServerURL+edvEndpointPathRoot,
		c.VaultID,
		encryptedFormatter,
		edv.WithTLSConfig(c.TLSConfig),
		edv.WithHeaders(func(req *http.Request) (*http.Header, error) {
			return c.signHeader(req, c.EDVCapability)
		}),
	)

	cachedProvider := cachedstore.NewProvider(restProvider, c.CacheProvider)

	return cachedProvider, nil
}

func (c *Config) signHeader(req *http.Request, edvCapability []byte) (*http.Header, error) {
	if len(edvCapability) != 0 {
		h, err := c.HeaderSigner.SignHeader(req, edvCapability)
		if err != nil {
			return nil, fmt.Errorf("sign header: %w", err)
		}

		return h, nil
	}

	return nil, nil
}

func (c *Config) createEncryptedFormatter(macCrypto *edv.MACCrypto) (*edv.EncryptedFormatter, error) {
	recipientKH, err := c.KeyManager.Get(c.RecipientKeyID)
	if err != nil {
		return nil, fmt.Errorf("get recipient key handle: %w", err)
	}

	pubKey, b, err := recipientPublicKey(recipientKH, c.RecipientKeyID)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(b, pubKey)
	if err != nil {
		return nil, fmt.Errorf("unmarshal bytes to a public key: %w", err)
	}

	encrypter, err := jose.NewJWEEncrypt(encAlg, encType, "", "", nil, []*crypto.PublicKey{pubKey}, c.CryptoService)
	if err != nil {
		return nil, fmt.Errorf("create JWEEncrypt: %w", err)
	}

	decrypter := jose.NewJWEDecrypt(nil, c.CryptoService, c.KeyManager)

	return edv.NewEncryptedFormatter(encrypter, decrypter, macCrypto, edv.WithDeterministicDocumentIDs()), nil
}

func recipientPublicKey(kh interface{}, keyID string) (*crypto.PublicKey, []byte, error) {
	pubKH, err := kh.(*keyset.Handle).Public()
	if err != nil {
		return nil, nil, fmt.Errorf("get public KH from recipient KH: %w", err)
	}

	buf := new(bytes.Buffer)
	keyWriter := keyio.NewWriter(buf)

	err = pubKH.WriteWithNoSecrets(keyWriter)
	if err != nil {
		return nil, nil, fmt.Errorf("write keyset: %w", err)
	}

	pubKey := new(crypto.PublicKey)
	pubKey.KID = keyID

	return pubKey, buf.Bytes(), nil
}
