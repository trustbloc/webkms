/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package edv //nolint:testpackage // need to test local methods

import (
	"crypto/tls"
	"errors"
	"net/http"
	"net/url"
	"testing"

	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/mac"
	"github.com/google/tink/go/signature"
	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite/ecdh"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	mockcrypto "github.com/hyperledger/aries-framework-go/pkg/mock/crypto"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/mock/kms"
	"github.com/stretchr/testify/require"
)

const (
	testEDVServerURL   = "edv.trustbloc.local"
	testRecipientKeyID = "recipientKeyID"
	testMACKeyID       = "macKeyID"
)

func TestSignHeader(t *testing.T) {
	t.Run("test error from sign header", func(t *testing.T) {
		expected := errors.New("failed to sign header")
		c := newConfig(t, withHeaderSigner(&mockHeaderSigner{signErr: expected}))

		h, err := c.signHeader(&http.Request{Header: make(map[string][]string), URL: &url.URL{}}, []byte("{}"))

		require.Error(t, err)
		require.True(t, errors.Is(err, expected))
		require.Nil(t, h)
	})

	t.Run("test empty zcap", func(t *testing.T) {
		c := newConfig(t)
		h, err := c.signHeader(&http.Request{Header: make(map[string][]string), URL: &url.URL{}}, nil)

		require.NoError(t, err)
		require.Nil(t, h)
	})
}

func TestNewStorageProvider(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		p, err := NewStorageProvider(newConfig(t))

		require.NotNil(t, p)
		require.NoError(t, err)
	})

	t.Run("Fail to create REST provider: get MAC key handle", func(t *testing.T) {
		c := newConfig(t)
		c.MACKeyID = "invalid key ID"

		p, err := NewStorageProvider(c)

		require.Nil(t, p)
		require.Error(t, err)
	})

	t.Run("Fail to create EncryptedFormatter: invalid recipient key ID", func(t *testing.T) {
		c := newConfig(t)
		c.RecipientKeyID = "invalid key ID"

		p, err := NewStorageProvider(c)

		require.Nil(t, p)
		require.Error(t, err)
	})

	t.Run("Fail to create EncryptedFormatter: get public key handle for recipient key", func(t *testing.T) {
		km := newMockKeyManager(t)

		kh, err := keyset.NewHandle(mac.HMACSHA256Tag256KeyTemplate())
		require.NoError(t, err)

		km.recipientKH = kh

		p, err := NewStorageProvider(newConfig(t, withKeyManager(km)))

		require.Nil(t, p)
		require.Error(t, err)
	})

	t.Run("Fail to create EncryptedFormatter: export keyset to the writer", func(t *testing.T) {
		km := newMockKeyManager(t)

		kh, err := keyset.NewHandle(signature.ECDSAP256KeyTemplate())
		require.NoError(t, err)

		km.recipientKH = kh

		p, err := NewStorageProvider(newConfig(t, withKeyManager(km)))

		require.Nil(t, p)
		require.Error(t, err)
	})
}

type options struct {
	keyManager    kms.KeyManager
	cryptoService crypto.Crypto
	headerSigner  HeaderSigner
}

type optionFn func(opts *options)

func newConfig(t *testing.T, opts ...optionFn) *Config {
	t.Helper()

	cOpts := &options{
		keyManager:    newMockKeyManager(t),
		cryptoService: &mockcrypto.Crypto{},
		headerSigner:  &mockHeaderSigner{},
	}

	for i := range opts {
		opts[i](cOpts)
	}

	return &Config{
		KeyManager:     cOpts.keyManager,
		CryptoService:  cOpts.cryptoService,
		HeaderSigner:   cOpts.headerSigner,
		CacheProvider:  nil,
		TLSConfig:      &tls.Config{MinVersion: tls.VersionTLS12},
		EDVCapability:  nil,
		EDVServerURL:   testEDVServerURL,
		VaultID:        "",
		RecipientKeyID: testRecipientKeyID,
		MACKeyID:       testMACKeyID,
	}
}

func withKeyManager(km kms.KeyManager) optionFn {
	return func(o *options) {
		o.keyManager = km
	}
}

func withHeaderSigner(s HeaderSigner) optionFn {
	return func(o *options) {
		o.headerSigner = s
	}
}

type mockKeyManager struct {
	recipientKH *keyset.Handle
	macKH       *keyset.Handle
	mockkms.KeyManager
}

func newMockKeyManager(t *testing.T) *mockKeyManager {
	t.Helper()

	recipientKH, err := keyset.NewHandle(ecdh.NISTP256ECDHKWKeyTemplate())
	require.NoError(t, err)

	macKH, err := keyset.NewHandle(mac.HMACSHA256Tag256KeyTemplate())
	require.NoError(t, err)

	return &mockKeyManager{
		recipientKH: recipientKH,
		macKH:       macKH,
		KeyManager:  mockkms.KeyManager{},
	}
}

func (m *mockKeyManager) Get(keyID string) (interface{}, error) {
	switch keyID {
	case testRecipientKeyID:
		return m.recipientKH, nil
	case testMACKeyID:
		return m.macKH, nil
	default:
		return nil, errors.New("invalid key ID")
	}
}

type mockHeaderSigner struct {
	signVal *http.Header
	signErr error
}

func (m *mockHeaderSigner) SignHeader(*http.Request, []byte) (*http.Header, error) {
	return m.signVal, m.signErr
}
