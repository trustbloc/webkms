/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package command_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/signature"
	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite/ecdh"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite/keyio"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	mockcrypto "github.com/hyperledger/aries-framework-go/pkg/mock/crypto"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/mock/kms"
	mockstorage "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/edge-core/pkg/zcapld"

	. "github.com/trustbloc/kms/pkg/controller/command"
)

func TestNew(t *testing.T) {
	t.Run("Fail to open key store db", func(t *testing.T) {
		store := mockstorage.NewMockStoreProvider()
		store.ErrOpenStoreHandle = errors.New("open store error")

		cmd, err := New(&Config{
			StorageProvider: store,
		})
		require.Nil(t, cmd)
		require.EqualError(t, err, "open key store db: open store error")
	})
}

func TestCommand_CreateDID(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		ctrl := gomock.NewController(t)

		zcap := NewMockZCAPService(ctrl)
		zcap.EXPECT().CreateDIDKey(context.Background()).Return("did:example:test", nil)

		cmd, err := New(&Config{
			StorageProvider: mockstorage.NewMockStoreProvider(),
			ZCAPService:     zcap,
			EnableZCAPs:     true,
		})
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var buf bytes.Buffer

		err = cmd.CreateDID(&buf, nil)
		require.NoError(t, err)

		var resp CreateDIDResponse

		err = json.Unmarshal(buf.Bytes(), &resp)
		require.NoError(t, err)
		require.Equal(t, "did:example:test", resp.DID)
	})

	t.Run("Fail to create a did:key", func(t *testing.T) {
		ctrl := gomock.NewController(t)

		zcap := NewMockZCAPService(ctrl)
		zcap.EXPECT().CreateDIDKey(context.Background()).Return("", errors.New("create did key error"))

		cmd, err := New(&Config{
			StorageProvider: mockstorage.NewMockStoreProvider(),
			ZCAPService:     zcap,
			EnableZCAPs:     true,
		})
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var buf bytes.Buffer

		err = cmd.CreateDID(&buf, nil)
		require.EqualError(t, err, "create did:key: create did key error")
	})
}

func TestCommand_CreateKeyStore(t *testing.T) {
	t.Run("Success with EDV storage", func(t *testing.T) {
		ctrl := gomock.NewController(t)

		cr, err := tinkcrypto.New()
		require.NoError(t, err)

		km := &mockkms.KeyManager{
			CrAndExportPubKeyValue: createRecipientPubKey(t),
		}

		creator := NewMockKeyStoreCreator(ctrl)
		creator.EXPECT().Create(gomock.Any(), gomock.Any()).Return(nil, nil).Times(1)

		zcap := NewMockZCAPService(ctrl)
		zcap.EXPECT().NewCapability(context.Background(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
			Return(&zcapld.Capability{}, nil).
			Times(1)

		cache := NewMockCacheProvider(ctrl)
		cache.EXPECT().Wrap(gomock.Any(), gomock.Any()).Times(1)

		cmd, err := New(&Config{
			StorageProvider:  mockstorage.NewMockStoreProvider(),
			KMS:              km,
			Crypto:           cr,
			KeyStoreCreator:  creator,
			ZCAPService:      zcap,
			EnableZCAPs:      true,
			CacheProvider:    cache,
			KeyStoreCacheTTL: 10 * time.Second,
		})
		require.NoError(t, err)
		require.NotNil(t, cmd)

		req, err := json.Marshal(CreateKeyStoreRequest{
			Controller: "did:example:test",
			EDV: &EDVOptions{
				VaultURL: "https://edv-host/encrypted-data-vaults/vault-id",
			},
		})
		require.NoError(t, err)

		wr, err := json.Marshal(WrappedRequest{
			Request: req,
		})
		require.NoError(t, err)

		var buf bytes.Buffer

		err = cmd.CreateKeyStore(&buf, bytes.NewBuffer(wr))
		require.NoError(t, err)
	})

	t.Run("Success with Shamir secret lock", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		cr, err := tinkcrypto.New()
		require.NoError(t, err)

		km := &mockkms.KeyManager{}

		creator := NewMockKeyStoreCreator(ctrl)
		creator.EXPECT().Create(gomock.Any(), gomock.Any()).Return(nil, nil).Times(1)

		shamirLockCreator := NewMockShamirSecretLockCreator(ctrl)
		shamirLockCreator.EXPECT().Create(gomock.Any()).Return(nil, nil).Times(1)

		shamirProvider := NewMockShamirProvider(ctrl)
		shamirProvider.EXPECT().FetchSecretShare(gomock.Any()).Return([]byte("secret share"), nil).Times(1)

		zcap := NewMockZCAPService(ctrl)
		zcap.EXPECT().NewCapability(context.Background(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
			Return(&zcapld.Capability{}, nil).
			Times(1)

		cmd, err := New(&Config{
			StorageProvider:         mockstorage.NewMockStoreProvider(),
			KMS:                     km,
			Crypto:                  cr,
			KeyStoreCreator:         creator,
			ShamirSecretLockCreator: shamirLockCreator,
			ZCAPService:             zcap,
			EnableZCAPs:             true,
			ShamirProvider:          shamirProvider,
		})
		require.NoError(t, err)
		require.NotNil(t, cmd)

		req, err := json.Marshal(CreateKeyStoreRequest{
			Controller: "did:example:test",
		})
		require.NoError(t, err)

		wr, err := json.Marshal(WrappedRequest{
			Request:     req,
			User:        "user",
			SecretShare: []byte("secret share"),
		})
		require.NoError(t, err)

		var buf bytes.Buffer

		err = cmd.CreateKeyStore(&buf, bytes.NewBuffer(wr))
		require.NoError(t, err)
	})

	t.Run("Fail to decode a wrapped request", func(t *testing.T) {
		cmd, err := New(&Config{
			StorageProvider: mockstorage.NewMockStoreProvider(),
		})
		require.NoError(t, err)
		require.NotNil(t, cmd)

		err = cmd.CreateKeyStore(nil, bytes.NewBuffer(nil))
		require.EqualError(t, err, "unwrap request: internal error: decode wrapped request")
	})

	t.Run("Fail to validate request", func(t *testing.T) {
		cmd, err := New(&Config{
			StorageProvider: mockstorage.NewMockStoreProvider(),
		})
		require.NoError(t, err)
		require.NotNil(t, cmd)

		req, err := json.Marshal(CreateKeyStoreRequest{
			Controller: "",
		})
		require.NoError(t, err)

		wr, err := json.Marshal(WrappedRequest{
			Request: req,
		})
		require.NoError(t, err)

		var buf bytes.Buffer

		err = cmd.CreateKeyStore(&buf, bytes.NewBuffer(wr))
		require.EqualError(t, err, "validate request: validation failed: controller must be non-empty")
	})

	t.Run("Fail to prepare EDV provider", func(t *testing.T) {
		cr, err := tinkcrypto.New()
		require.NoError(t, err)

		km := &mockkms.KeyManager{
			CrAndExportPubKeyErr: errors.New("create pub key error"),
		}

		cmd, err := New(&Config{
			StorageProvider: mockstorage.NewMockStoreProvider(),
			KMS:             km,
			Crypto:          cr,
		})
		require.NoError(t, err)
		require.NotNil(t, cmd)

		req, err := json.Marshal(CreateKeyStoreRequest{
			Controller: "did:example:test",
			EDV: &EDVOptions{
				VaultURL: "https://edv-host/encrypted-data-vaults/vault-id",
			},
		})
		require.NoError(t, err)

		wr, err := json.Marshal(WrappedRequest{
			Request: req,
		})
		require.NoError(t, err)

		var buf bytes.Buffer

		err = cmd.CreateKeyStore(&buf, bytes.NewBuffer(wr))
		require.EqualError(t, err, "prepare edv provider: create edv recipient key: create key: create pub key error")
	})

	t.Run("Fail to fetch secret share from auth server", func(t *testing.T) {
		ctrl := gomock.NewController(t)

		cr, err := tinkcrypto.New()
		require.NoError(t, err)

		km := &mockkms.KeyManager{}

		shamirProvider := NewMockShamirProvider(ctrl)
		shamirProvider.EXPECT().FetchSecretShare(gomock.Any()).Return(nil, errors.New("bad request")).Times(1)

		cmd, err := New(&Config{
			StorageProvider: mockstorage.NewMockStoreProvider(),
			KMS:             km,
			Crypto:          cr,
			ShamirProvider:  shamirProvider,
		})
		require.NoError(t, err)
		require.NotNil(t, cmd)

		req, err := json.Marshal(CreateKeyStoreRequest{
			Controller: "did:example:test",
		})
		require.NoError(t, err)

		wr, err := json.Marshal(WrappedRequest{
			Request:     req,
			User:        "user",
			SecretShare: []byte("secret share"),
		})
		require.NoError(t, err)

		var buf bytes.Buffer

		err = cmd.CreateKeyStore(&buf, bytes.NewBuffer(wr))
		require.EqualError(t, err, "create shamir secret lock: fetch secret share: bad request")
	})

	t.Run("Fail to create Shamir secret share with empty user", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		shamirProvider := NewMockShamirProvider(ctrl)
		shamirProvider.EXPECT().FetchSecretShare(gomock.Any()).Times(0)

		cmd, err := New(&Config{
			StorageProvider: mockstorage.NewMockStoreProvider(),
			KMS:             &mockkms.KeyManager{},
			ShamirProvider:  shamirProvider,
		})
		require.NoError(t, err)
		require.NotNil(t, cmd)

		req, err := json.Marshal(CreateKeyStoreRequest{
			Controller: "did:example:test",
		})
		require.NoError(t, err)

		wr, err := json.Marshal(WrappedRequest{
			Request:     req,
			SecretShare: []byte("secret share"),
		})
		require.NoError(t, err)

		var buf bytes.Buffer

		err = cmd.CreateKeyStore(&buf, bytes.NewBuffer(wr))
		require.EqualError(t, err, "create shamir secret lock: validation failed: empty user")
	})

	t.Run("Fail to create Shamir secret share with empty secret share", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		shamirProvider := NewMockShamirProvider(ctrl)
		shamirProvider.EXPECT().FetchSecretShare(gomock.Any()).Times(0)

		cmd, err := New(&Config{
			StorageProvider: mockstorage.NewMockStoreProvider(),
			KMS:             &mockkms.KeyManager{},
			ShamirProvider:  shamirProvider,
		})
		require.NoError(t, err)
		require.NotNil(t, cmd)

		req, err := json.Marshal(CreateKeyStoreRequest{
			Controller: "did:example:test",
		})
		require.NoError(t, err)

		wr, err := json.Marshal(WrappedRequest{
			Request: req,
			User:    "user",
		})
		require.NoError(t, err)

		var buf bytes.Buffer

		err = cmd.CreateKeyStore(&buf, bytes.NewBuffer(wr))
		require.EqualError(t, err, "create shamir secret lock: validation failed: empty secret share")
	})

	t.Run("Fail to create main key for key-based secret lock", func(t *testing.T) {
		cr, err := tinkcrypto.New()
		require.NoError(t, err)

		km := &mockkms.KeyManager{
			CreateKeyErr: errors.New("create key error"),
		}

		cmd, err := New(&Config{
			StorageProvider: mockstorage.NewMockStoreProvider(),
			KMS:             km,
			Crypto:          cr,
		})
		require.NoError(t, err)
		require.NotNil(t, cmd)

		req, err := json.Marshal(CreateKeyStoreRequest{
			Controller: "did:example:test",
		})
		require.NoError(t, err)

		wr, err := json.Marshal(WrappedRequest{
			Request: req,
		})
		require.NoError(t, err)

		var buf bytes.Buffer

		err = cmd.CreateKeyStore(&buf, bytes.NewBuffer(wr))
		require.EqualError(t, err, "create main key: create key error")
	})

	t.Run("Fail to create a key store", func(t *testing.T) {
		ctrl := gomock.NewController(t)

		cr, err := tinkcrypto.New()
		require.NoError(t, err)

		creator := NewMockKeyStoreCreator(ctrl)
		creator.EXPECT().Create(gomock.Any(), gomock.Any()).Return(nil, errors.New("create error")).Times(1)

		cmd, err := New(&Config{
			StorageProvider: mockstorage.NewMockStoreProvider(),
			KMS:             &mockkms.KeyManager{},
			Crypto:          cr,
			KeyStoreCreator: creator,
		})
		require.NoError(t, err)
		require.NotNil(t, cmd)

		req, err := json.Marshal(CreateKeyStoreRequest{
			Controller: "did:example:test",
		})
		require.NoError(t, err)

		wr, err := json.Marshal(WrappedRequest{
			Request: req,
		})
		require.NoError(t, err)

		var buf bytes.Buffer

		err = cmd.CreateKeyStore(&buf, bytes.NewBuffer(wr))
		require.EqualError(t, err, "create key store: create error")
	})

	t.Run("Fail to create ZCAPs", func(t *testing.T) {
		ctrl := gomock.NewController(t)

		cr, err := tinkcrypto.New()
		require.NoError(t, err)

		creator := NewMockKeyStoreCreator(ctrl)
		creator.EXPECT().Create(gomock.Any(), gomock.Any()).Return(nil, nil).Times(1)

		zcap := NewMockZCAPService(ctrl)
		zcap.EXPECT().NewCapability(context.Background(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
			Return(nil, errors.New("create capability error")).
			Times(1)

		cmd, err := New(&Config{
			StorageProvider: mockstorage.NewMockStoreProvider(),
			KMS:             &mockkms.KeyManager{},
			Crypto:          cr,
			KeyStoreCreator: creator,
			ZCAPService:     zcap,
			EnableZCAPs:     true,
		})
		require.NoError(t, err)
		require.NotNil(t, cmd)

		req, err := json.Marshal(CreateKeyStoreRequest{
			Controller: "did:example:test",
		})
		require.NoError(t, err)

		wr, err := json.Marshal(WrappedRequest{
			Request: req,
		})
		require.NoError(t, err)

		var buf bytes.Buffer

		err = cmd.CreateKeyStore(&buf, bytes.NewBuffer(wr))
		require.EqualError(t, err, "new compressed zcap: create zcap: create capability error")
	})

	t.Run("Fail to save key store metadata", func(t *testing.T) {
		ctrl := gomock.NewController(t)

		cr, err := tinkcrypto.New()
		require.NoError(t, err)

		creator := NewMockKeyStoreCreator(ctrl)
		creator.EXPECT().Create(gomock.Any(), gomock.Any()).Return(nil, nil).Times(1)

		zcap := NewMockZCAPService(ctrl)
		zcap.EXPECT().NewCapability(context.Background(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
			Return(&zcapld.Capability{}, nil).
			Times(1)

		store := mockstorage.NewMockStoreProvider()
		store.Store.ErrPut = errors.New("put error")

		cmd, err := New(&Config{
			StorageProvider: store,
			KMS:             &mockkms.KeyManager{},
			Crypto:          cr,
			KeyStoreCreator: creator,
			ZCAPService:     zcap,
			EnableZCAPs:     true,
		})
		require.NoError(t, err)
		require.NotNil(t, cmd)

		req, err := json.Marshal(CreateKeyStoreRequest{
			Controller: "did:example:test",
		})
		require.NoError(t, err)

		wr, err := json.Marshal(WrappedRequest{
			Request: req,
		})
		require.NoError(t, err)

		var buf bytes.Buffer

		err = cmd.CreateKeyStore(&buf, bytes.NewBuffer(wr))
		require.EqualError(t, err, "save key store metadata: put: put error")
	})
}

func TestCommand_CreateKey(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		cmd := createCmd(t, gomock.NewController(t), withKeyManager(&mockkms.KeyManager{
			CreateKeyID: "key_id",
		}))

		req, err := json.Marshal(CreateKeyRequest{
			KeyType: kms.ED25519,
		})
		require.NoError(t, err)

		wr, err := json.Marshal(WrappedRequest{
			KeyStoreID: "key_store_id",
			Request:    req,
		})
		require.NoError(t, err)

		var buf bytes.Buffer

		err = cmd.CreateKey(&buf, bytes.NewBuffer(wr))
		require.NoError(t, err)

		var resp CreateKeyResponse

		err = json.Unmarshal(buf.Bytes(), &resp)
		require.NoError(t, err)
		require.Equal(t, "/key_store_id/keys/key_id", resp.KeyURL)
	})

	t.Run("Success with EDV storage and Shamir secret lock", func(t *testing.T) {
		keyStoreData := []byte(`{
		  "id": "key_store_id",
		  "controller": "controller",
		  "edv": {
			"vault_url": "https://edv-host/encrypted-data-vaults/vault-id"
		  }
		}`)

		p := mockstorage.NewMockStoreProvider()
		p.Store.Store["key_store_id"] = mockstorage.DBEntry{Value: keyStoreData}

		km := &mockkms.KeyManager{
			ExportPubKeyBytesValue: createRecipientPubKey(t),
			CreateKeyID:            "key_id",
		}

		ctrl := gomock.NewController(t)

		shamirLockCreator := NewMockShamirSecretLockCreator(ctrl)
		shamirLockCreator.EXPECT().Create(gomock.Any()).Return(nil, nil).Times(1)

		shamirProvider := NewMockShamirProvider(ctrl)
		shamirProvider.EXPECT().FetchSecretShare(gomock.Any()).Return([]byte("secret share"), nil).Times(1)

		cmd := createCmd(t, ctrl,
			withStorageProvider(p), withKeyManager(km), withShamirSecretLockCreator(shamirLockCreator),
			withShamirProvider(shamirProvider))

		req, err := json.Marshal(CreateKeyRequest{
			KeyType: kms.ED25519,
		})
		require.NoError(t, err)

		wr, err := json.Marshal(WrappedRequest{
			KeyStoreID:  "key_store_id",
			User:        "user",
			SecretShare: []byte("secret share"),
			Request:     req,
		})
		require.NoError(t, err)

		var buf bytes.Buffer

		err = cmd.CreateKey(&buf, bytes.NewBuffer(wr))
		require.NoError(t, err)

		var resp CreateKeyResponse

		err = json.Unmarshal(buf.Bytes(), &resp)
		require.NoError(t, err)
		require.Equal(t, "/key_store_id/keys/key_id", resp.KeyURL)
	})

	t.Run("Fail to decode wrapped request", func(t *testing.T) {
		cmd, err := New(&Config{
			StorageProvider: mockstorage.NewMockStoreProvider(),
		})
		require.NoError(t, err)
		require.NotNil(t, cmd)

		err = cmd.CreateKey(nil, bytes.NewBuffer(nil))
		require.EqualError(t, err, "unwrap request: internal error: decode wrapped request")
	})

	t.Run("Fail to decode payload request", func(t *testing.T) {
		cmd, err := New(&Config{
			StorageProvider: mockstorage.NewMockStoreProvider(),
		})
		require.NoError(t, err)
		require.NotNil(t, cmd)

		wr, err := json.Marshal(WrappedRequest{
			KeyStoreID: "key_store_id",
			Request:    nil,
		})
		require.NoError(t, err)

		var buf bytes.Buffer

		err = cmd.CreateKey(&buf, bytes.NewBuffer(wr))
		require.EqualError(t, err, "unwrap request: internal error: decode request")
	})

	t.Run("Fail to get a key store meta data", func(t *testing.T) {
		ctrl := gomock.NewController(t)

		metrics := NewMockMetricsProvider(ctrl)
		metrics.EXPECT().KeyStoreResolveTime(gomock.Any()).Times(1)

		cmd, err := New(&Config{
			StorageProvider: mockstorage.NewMockStoreProvider(),
			MetricsProvider: metrics,
		})
		require.NoError(t, err)
		require.NotNil(t, cmd)

		req, err := json.Marshal(CreateKeyRequest{
			KeyType: kms.ED25519,
		})
		require.NoError(t, err)

		wr, err := json.Marshal(WrappedRequest{
			KeyStoreID: "key_store_id",
			Request:    req,
		})
		require.NoError(t, err)

		var buf bytes.Buffer

		err = cmd.CreateKey(&buf, bytes.NewBuffer(wr))
		require.EqualError(t, err, "resolve key store: get key store meta: data not found")
	})

	t.Run("Fail to create a key", func(t *testing.T) {
		cmd := createCmd(t, gomock.NewController(t), withKeyManager(&mockkms.KeyManager{
			CreateKeyErr: errors.New("create key error"),
		}))

		req, err := json.Marshal(CreateKeyRequest{
			KeyType: kms.ED25519,
		})
		require.NoError(t, err)

		wr, err := json.Marshal(WrappedRequest{
			KeyStoreID: "key_store_id",
			Request:    req,
		})
		require.NoError(t, err)

		var buf bytes.Buffer

		err = cmd.CreateKey(&buf, bytes.NewBuffer(wr))
		require.EqualError(t, err, "create key: create key error")
	})

	t.Run("Fail to export public key bytes", func(t *testing.T) {
		cmd := createCmd(t, gomock.NewController(t), withKeyManager(&mockkms.KeyManager{
			ExportPubKeyBytesErr: errors.New("export key error"),
		}))

		req, err := json.Marshal(CreateKeyRequest{
			KeyType: kms.ED25519,
		})
		require.NoError(t, err)

		wr, err := json.Marshal(WrappedRequest{
			KeyStoreID: "key_store_id",
			Request:    req,
		})
		require.NoError(t, err)

		var buf bytes.Buffer

		err = cmd.CreateKey(&buf, bytes.NewBuffer(wr))
		require.EqualError(t, err, "export public key bytes: export key error")
	})
}

func TestCommand_ExportKey(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		cmd := createCmd(t, gomock.NewController(t), withKeyManager(&mockkms.KeyManager{
			ExportPubKeyBytesValue: []byte("public key bytes"),
		}))

		wr, err := json.Marshal(WrappedRequest{
			KeyStoreID: "key_store_id",
			KeyID:      "key_id",
		})
		require.NoError(t, err)

		var buf bytes.Buffer

		err = cmd.ExportKey(&buf, bytes.NewBuffer(wr))
		require.NoError(t, err)

		var resp ExportKeyResponse

		err = json.Unmarshal(buf.Bytes(), &resp)
		require.NoError(t, err)
		require.Equal(t, []byte("public key bytes"), resp.PublicKey)
	})

	t.Run("Fail to export public key bytes", func(t *testing.T) {
		cmd := createCmd(t, gomock.NewController(t), withKeyManager(&mockkms.KeyManager{
			ExportPubKeyBytesErr: errors.New("export key error"),
		}))

		wr, err := json.Marshal(WrappedRequest{
			KeyStoreID: "key_store_id",
			KeyID:      "key_id",
		})
		require.NoError(t, err)

		var buf bytes.Buffer

		err = cmd.ExportKey(&buf, bytes.NewBuffer(wr))
		require.EqualError(t, err, "export public key bytes: export key error")
	})
}

func TestCommand_ImportKey(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		tests := []struct {
			kt kms.KeyType
		}{
			{kms.ED25519},
			{kms.ECDSAP256TypeDER},
			{kms.ECDSAP384TypeDER},
			{kms.ECDSAP521TypeDER},
			{kms.ECDSAP256TypeIEEEP1363},
			{kms.ECDSAP384TypeIEEEP1363},
			{kms.ECDSAP521TypeIEEEP1363},
		}

		for _, tt := range tests {
			t.Run(fmt.Sprintf("import_%s", tt.kt), func(t *testing.T) {
				cmd := createCmd(t, gomock.NewController(t), withKeyManager(&mockkms.KeyManager{
					ImportPrivateKeyID: "key_id",
				}))

				pk := createPrivateKey(t, tt.kt)

				der, err := x509.MarshalPKCS8PrivateKey(pk)
				require.NoError(t, err)

				req, err := json.Marshal(ImportKeyRequest{
					KeyID:   "key_id",
					KeyType: tt.kt,
					Key:     der,
				})
				require.NoError(t, err)

				wr, err := json.Marshal(WrappedRequest{
					KeyStoreID: "key_store_id",
					Request:    req,
				})
				require.NoError(t, err)

				var buf bytes.Buffer

				err = cmd.ImportKey(&buf, bytes.NewBuffer(wr))
				require.NoError(t, err)

				var resp ImportKeyResponse

				err = json.Unmarshal(buf.Bytes(), &resp)
				require.NoError(t, err)
				require.Equal(t, "/key_store_id/keys/key_id", resp.KeyURL)
			})
		}
	})

	t.Run("Fail to parse private key", func(t *testing.T) {
		cmd := createCmd(t, gomock.NewController(t))

		req, err := json.Marshal(ImportKeyRequest{
			KeyID:   "key_id",
			KeyType: kms.ED25519,
			Key:     nil,
		})
		require.NoError(t, err)

		wr, err := json.Marshal(WrappedRequest{
			KeyStoreID: "key_store_id",
			Request:    req,
		})
		require.NoError(t, err)

		var buf bytes.Buffer

		err = cmd.ImportKey(&buf, bytes.NewBuffer(wr))
		require.Contains(t, err.Error(), "parse private key")
	})

	t.Run("Not supported key type", func(t *testing.T) {
		cmd := createCmd(t, gomock.NewController(t))

		req, err := json.Marshal(ImportKeyRequest{
			KeyID:   "key_id",
			KeyType: "invalid",
		})
		require.NoError(t, err)

		wr, err := json.Marshal(WrappedRequest{
			KeyStoreID: "key_store_id",
			Request:    req,
		})
		require.NoError(t, err)

		var buf bytes.Buffer

		err = cmd.ImportKey(&buf, bytes.NewBuffer(wr))
		require.EqualError(t, err, "not supported key type: invalid")
	})

	t.Run("Fail to import private key", func(t *testing.T) {
		cmd := createCmd(t, gomock.NewController(t), withKeyManager(&mockkms.KeyManager{
			ImportPrivateKeyErr: errors.New("import private key error"),
		}))

		pk := createPrivateKey(t, kms.ED25519)

		der, err := x509.MarshalPKCS8PrivateKey(pk)
		require.NoError(t, err)

		req, err := json.Marshal(ImportKeyRequest{
			KeyID:   "key_id",
			KeyType: kms.ED25519,
			Key:     der,
		})
		require.NoError(t, err)

		wr, err := json.Marshal(WrappedRequest{
			KeyStoreID: "key_store_id",
			Request:    req,
		})
		require.NoError(t, err)

		var buf bytes.Buffer

		err = cmd.ImportKey(&buf, bytes.NewBuffer(wr))
		require.EqualError(t, err, "import private key: import private key error")
	})
}

func TestCommand_RotateKey(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		cmd := createCmd(t, gomock.NewController(t), withKeyManager(&mockkms.KeyManager{
			RotateKeyID: "rotate_key_id",
		}))

		req, err := json.Marshal(RotateKeyRequest{
			KeyType: kms.ED25519,
		})
		require.NoError(t, err)

		wr, err := json.Marshal(WrappedRequest{
			KeyStoreID: "key_store_id",
			KeyID:      "key_id",
			Request:    req,
		})
		require.NoError(t, err)

		var buf bytes.Buffer

		err = cmd.RotateKey(&buf, bytes.NewBuffer(wr))
		require.NoError(t, err)

		var resp RotateKeyResponse

		err = json.Unmarshal(buf.Bytes(), &resp)
		require.NoError(t, err)
		require.Contains(t, resp.KeyURL, "rotate_key_id")
	})

	t.Run("Fail to decode wrapped request", func(t *testing.T) {
		cmd, err := New(&Config{
			StorageProvider: mockstorage.NewMockStoreProvider(),
		})
		require.NoError(t, err)
		require.NotNil(t, cmd)

		err = cmd.RotateKey(nil, bytes.NewBuffer(nil))
		require.EqualError(t, err, "unwrap request: internal error: decode wrapped request")
	})

	t.Run("Fail to get a key store meta data", func(t *testing.T) {
		ctrl := gomock.NewController(t)

		metrics := NewMockMetricsProvider(ctrl)
		metrics.EXPECT().KeyStoreResolveTime(gomock.Any()).Times(1)

		cmd, err := New(&Config{
			StorageProvider: mockstorage.NewMockStoreProvider(),
			MetricsProvider: metrics,
		})
		require.NoError(t, err)
		require.NotNil(t, cmd)

		req, err := json.Marshal(RotateKeyRequest{
			KeyType: kms.ED25519,
		})
		require.NoError(t, err)

		wr, err := json.Marshal(WrappedRequest{
			KeyStoreID: "key_store_id",
			Request:    req,
		})
		require.NoError(t, err)

		var buf bytes.Buffer

		err = cmd.RotateKey(&buf, bytes.NewBuffer(wr))
		require.EqualError(t, err, "resolve key store: get key store meta: data not found")
	})

	t.Run("Fail to rotate a key", func(t *testing.T) {
		cmd := createCmd(t, gomock.NewController(t), withKeyManager(&mockkms.KeyManager{
			RotateKeyErr: errors.New("rotate key error"),
		}))

		req, err := json.Marshal(RotateKeyRequest{
			KeyType: kms.ED25519,
		})
		require.NoError(t, err)

		wr, err := json.Marshal(WrappedRequest{
			KeyStoreID: "key_store_id",
			KeyID:      "key_id",
			Request:    req,
		})
		require.NoError(t, err)

		var buf bytes.Buffer

		err = cmd.RotateKey(&buf, bytes.NewBuffer(wr))
		require.EqualError(t, err, "rotate key: rotate key error")
	})
}

func TestCommand_Sign(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		cmd := createCmd(t, gomock.NewController(t), withCrypto(&mockcrypto.Crypto{
			SignValue: []byte("signature"),
		}))

		req, err := json.Marshal(SignRequest{
			Message: []byte("test message"),
		})
		require.NoError(t, err)

		wr, err := json.Marshal(WrappedRequest{
			KeyStoreID: "key_store_id",
			KeyID:      "key_id",
			Request:    req,
		})
		require.NoError(t, err)

		var buf bytes.Buffer

		err = cmd.Sign(&buf, bytes.NewBuffer(wr))
		require.NoError(t, err)

		var resp SignResponse

		err = json.Unmarshal(buf.Bytes(), &resp)
		require.NoError(t, err)
		require.Equal(t, []byte("signature"), resp.Signature)
	})

	t.Run("Fail to sign", func(t *testing.T) {
		cmd := createCmd(t, gomock.NewController(t), withCrypto(&mockcrypto.Crypto{
			SignErr: errors.New("sign error"),
		}))

		req, err := json.Marshal(SignRequest{
			Message: []byte("test message"),
		})
		require.NoError(t, err)

		wr, err := json.Marshal(WrappedRequest{
			KeyStoreID: "key_store_id",
			KeyID:      "key_id",
			Request:    req,
		})
		require.NoError(t, err)

		var buf bytes.Buffer

		err = cmd.Sign(&buf, bytes.NewBuffer(wr))
		require.EqualError(t, err, "sign: sign error")
	})
}

func TestCommand_Verify(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		kh, err := keyset.NewHandle(signature.ED25519KeyTemplate())
		require.NoError(t, err)

		cmd := createCmd(t, gomock.NewController(t),
			withKeyManager(&mockkms.KeyManager{GetKeyValue: kh}),
			withCrypto(&mockcrypto.Crypto{}),
		)

		req, err := json.Marshal(VerifyRequest{
			Signature: []byte("signature"),
			Message:   []byte("test message"),
		})
		require.NoError(t, err)

		wr, err := json.Marshal(WrappedRequest{
			KeyStoreID: "key_store_id",
			KeyID:      "key_id",
			Request:    req,
		})
		require.NoError(t, err)

		err = cmd.Verify(nil, bytes.NewBuffer(wr))
		require.NoError(t, err)
	})

	t.Run("Fail to get public key from handle", func(t *testing.T) {
		badKH, err := keyset.NewHandle(aead.KMSEnvelopeAEADKeyTemplate("badUrl", nil))
		require.NoError(t, err)

		cmd := createCmd(t, gomock.NewController(t),
			withKeyManager(&mockkms.KeyManager{GetKeyValue: badKH}),
			withCrypto(&mockcrypto.Crypto{}),
		)

		req, err := json.Marshal(VerifyRequest{
			Signature: []byte("signature"),
			Message:   []byte("test message"),
		})
		require.NoError(t, err)

		wr, err := json.Marshal(WrappedRequest{
			KeyStoreID: "key_store_id",
			KeyID:      "key_id",
			Request:    req,
		})
		require.NoError(t, err)

		err = cmd.Verify(nil, bytes.NewBuffer(wr))
		require.Error(t, err)
	})

	t.Run("Fail to verify", func(t *testing.T) {
		kh, err := keyset.NewHandle(signature.ED25519KeyTemplate())
		require.NoError(t, err)

		cmd := createCmd(t, gomock.NewController(t),
			withKeyManager(&mockkms.KeyManager{GetKeyValue: kh}),
			withCrypto(&mockcrypto.Crypto{VerifyErr: errors.New("verify error")}),
		)

		req, err := json.Marshal(VerifyRequest{
			Signature: []byte("signature"),
			Message:   []byte("test message"),
		})
		require.NoError(t, err)

		wr, err := json.Marshal(WrappedRequest{
			KeyStoreID: "key_store_id",
			KeyID:      "key_id",
			Request:    req,
		})
		require.NoError(t, err)

		err = cmd.Verify(nil, bytes.NewBuffer(wr))
		require.EqualError(t, err, "verify: verify error")
	})
}

func TestCommand_Encrypt(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		cmd := createCmd(t, gomock.NewController(t), withCrypto(&mockcrypto.Crypto{
			EncryptValue:      []byte("ciphertext"),
			EncryptNonceValue: []byte("nonce"),
		}))

		req, err := json.Marshal(EncryptRequest{
			Message: []byte("test message"),
		})
		require.NoError(t, err)

		wr, err := json.Marshal(WrappedRequest{
			KeyStoreID: "key_store_id",
			KeyID:      "key_id",
			Request:    req,
		})
		require.NoError(t, err)

		var buf bytes.Buffer

		err = cmd.Encrypt(&buf, bytes.NewBuffer(wr))
		require.NoError(t, err)

		var resp EncryptResponse

		err = json.Unmarshal(buf.Bytes(), &resp)
		require.NoError(t, err)
		require.Equal(t, []byte("ciphertext"), resp.Ciphertext)
		require.Equal(t, []byte("nonce"), resp.Nonce)
	})

	t.Run("Fail to encrypt", func(t *testing.T) {
		cmd := createCmd(t, gomock.NewController(t), withCrypto(&mockcrypto.Crypto{
			EncryptErr: errors.New("encrypt error"),
		}))

		req, err := json.Marshal(EncryptRequest{
			Message: []byte("test message"),
		})
		require.NoError(t, err)

		wr, err := json.Marshal(WrappedRequest{
			KeyStoreID: "key_store_id",
			KeyID:      "key_id",
			Request:    req,
		})
		require.NoError(t, err)

		var buf bytes.Buffer

		err = cmd.Encrypt(&buf, bytes.NewBuffer(wr))
		require.EqualError(t, err, "encrypt: encrypt error")
	})
}

func TestCommand_Decrypt(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		cmd := createCmd(t, gomock.NewController(t), withCrypto(&mockcrypto.Crypto{
			DecryptValue: []byte("plaintext"),
		}))

		req, err := json.Marshal(DecryptRequest{
			Ciphertext:     []byte("ciphertext"),
			AssociatedData: []byte("ad"),
			Nonce:          []byte("nonce"),
		})
		require.NoError(t, err)

		wr, err := json.Marshal(WrappedRequest{
			KeyStoreID: "key_store_id",
			KeyID:      "key_id",
			Request:    req,
		})
		require.NoError(t, err)

		var buf bytes.Buffer

		err = cmd.Decrypt(&buf, bytes.NewBuffer(wr))
		require.NoError(t, err)

		var resp DecryptResponse

		err = json.Unmarshal(buf.Bytes(), &resp)
		require.NoError(t, err)
		require.Equal(t, []byte("plaintext"), resp.Plaintext)
	})

	t.Run("Fail to decrypt", func(t *testing.T) {
		cmd := createCmd(t, gomock.NewController(t), withCrypto(&mockcrypto.Crypto{
			DecryptErr: errors.New("decrypt error"),
		}))

		req, err := json.Marshal(DecryptRequest{
			Ciphertext:     []byte("ciphertext"),
			AssociatedData: []byte("ad"),
			Nonce:          []byte("nonce"),
		})
		require.NoError(t, err)

		wr, err := json.Marshal(WrappedRequest{
			KeyStoreID: "key_store_id",
			KeyID:      "key_id",
			Request:    req,
		})
		require.NoError(t, err)

		var buf bytes.Buffer

		err = cmd.Decrypt(&buf, bytes.NewBuffer(wr))
		require.EqualError(t, err, "decrypt: decrypt error")
	})
}

func TestCommand_ComputeMAC(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		cmd := createCmd(t, gomock.NewController(t), withCrypto(&mockcrypto.Crypto{
			ComputeMACValue: []byte("mac"),
		}))

		req, err := json.Marshal(ComputeMACRequest{
			Data: []byte("data"),
		})
		require.NoError(t, err)

		wr, err := json.Marshal(WrappedRequest{
			KeyStoreID: "key_store_id",
			KeyID:      "key_id",
			Request:    req,
		})
		require.NoError(t, err)

		var buf bytes.Buffer

		err = cmd.ComputeMAC(&buf, bytes.NewBuffer(wr))
		require.NoError(t, err)

		var resp ComputeMACResponse

		err = json.Unmarshal(buf.Bytes(), &resp)
		require.NoError(t, err)
		require.Equal(t, []byte("mac"), resp.MAC)
	})

	t.Run("Fail to compute MAC", func(t *testing.T) {
		cmd := createCmd(t, gomock.NewController(t), withCrypto(&mockcrypto.Crypto{
			ComputeMACErr: errors.New("compute mac error"),
		}))

		req, err := json.Marshal(ComputeMACRequest{
			Data: []byte("data"),
		})
		require.NoError(t, err)

		wr, err := json.Marshal(WrappedRequest{
			KeyStoreID: "key_store_id",
			KeyID:      "key_id",
			Request:    req,
		})
		require.NoError(t, err)

		var buf bytes.Buffer

		err = cmd.ComputeMAC(&buf, bytes.NewBuffer(wr))
		require.EqualError(t, err, "compute mac: compute mac error")
	})
}

func TestCommand_VerifyMAC(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		cmd := createCmd(t, gomock.NewController(t), withCrypto(&mockcrypto.Crypto{}))

		req, err := json.Marshal(VerifyMACRequest{
			Data: []byte("data"),
			MAC:  []byte("mac"),
		})
		require.NoError(t, err)

		wr, err := json.Marshal(WrappedRequest{
			KeyStoreID: "key_store_id",
			KeyID:      "key_id",
			Request:    req,
		})
		require.NoError(t, err)

		err = cmd.VerifyMAC(nil, bytes.NewBuffer(wr))
		require.NoError(t, err)
	})

	t.Run("Fail to verify MAC", func(t *testing.T) {
		cmd := createCmd(t, gomock.NewController(t), withCrypto(&mockcrypto.Crypto{
			VerifyMACErr: errors.New("verify mac error"),
		}))

		req, err := json.Marshal(VerifyMACRequest{
			Data: []byte("data"),
			MAC:  []byte("mac"),
		})
		require.NoError(t, err)

		wr, err := json.Marshal(WrappedRequest{
			KeyStoreID: "key_store_id",
			KeyID:      "key_id",
			Request:    req,
		})
		require.NoError(t, err)

		err = cmd.VerifyMAC(nil, bytes.NewBuffer(wr))
		require.EqualError(t, err, "verify mac: verify mac error")
	})
}

func TestCommand_SignMulti(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		cmd := createCmd(t, gomock.NewController(t), withCrypto(&mockcrypto.Crypto{
			BBSSignValue: []byte("signature"),
		}))

		req, err := json.Marshal(SignMultiRequest{
			Messages: [][]byte{
				[]byte("test message 1"),
				[]byte("test message 2"),
			},
		})
		require.NoError(t, err)

		wr, err := json.Marshal(WrappedRequest{
			KeyStoreID: "key_store_id",
			KeyID:      "key_id",
			Request:    req,
		})
		require.NoError(t, err)

		var buf bytes.Buffer

		err = cmd.SignMulti(&buf, bytes.NewBuffer(wr))
		require.NoError(t, err)

		var resp SignMultiResponse

		err = json.Unmarshal(buf.Bytes(), &resp)
		require.NoError(t, err)
		require.Equal(t, []byte("signature"), resp.Signature)
	})

	t.Run("Fail to sign multi", func(t *testing.T) {
		cmd := createCmd(t, gomock.NewController(t), withCrypto(&mockcrypto.Crypto{
			BBSSignErr: errors.New("sign error"),
		}))

		req, err := json.Marshal(SignMultiRequest{
			Messages: [][]byte{
				[]byte("test message 1"),
				[]byte("test message 2"),
			},
		})
		require.NoError(t, err)

		wr, err := json.Marshal(WrappedRequest{
			KeyStoreID: "key_store_id",
			KeyID:      "key_id",
			Request:    req,
		})
		require.NoError(t, err)

		var buf bytes.Buffer

		err = cmd.SignMulti(&buf, bytes.NewBuffer(wr))
		require.EqualError(t, err, "sign multi: sign error")
	})
}

func TestCommand_VerifyMulti(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		kh, err := keyset.NewHandle(signature.ED25519KeyTemplate())
		require.NoError(t, err)

		cmd := createCmd(t, gomock.NewController(t),
			withKeyManager(&mockkms.KeyManager{GetKeyValue: kh}),
			withCrypto(&mockcrypto.Crypto{}),
		)

		req, err := json.Marshal(VerifyMultiRequest{
			Messages: [][]byte{
				[]byte("test message 1"),
				[]byte("test message 2"),
			},
			Signature: []byte("signature"),
		})
		require.NoError(t, err)

		wr, err := json.Marshal(WrappedRequest{
			KeyStoreID: "key_store_id",
			KeyID:      "key_id",
			Request:    req,
		})
		require.NoError(t, err)

		err = cmd.VerifyMulti(nil, bytes.NewBuffer(wr))
		require.NoError(t, err)
	})

	t.Run("Fail to verify a signature", func(t *testing.T) {
		kh, err := keyset.NewHandle(signature.ED25519KeyTemplate())
		require.NoError(t, err)

		cmd := createCmd(t, gomock.NewController(t),
			withKeyManager(&mockkms.KeyManager{GetKeyValue: kh}),
			withCrypto(&mockcrypto.Crypto{
				BBSVerifyErr: errors.New("verify error"),
			}),
		)

		req, err := json.Marshal(VerifyMultiRequest{
			Messages: [][]byte{
				[]byte("test message 1"),
				[]byte("test message 2"),
			},
			Signature: []byte("signature"),
		})
		require.NoError(t, err)

		wr, err := json.Marshal(WrappedRequest{
			KeyStoreID: "key_store_id",
			KeyID:      "key_id",
			Request:    req,
		})
		require.NoError(t, err)

		err = cmd.VerifyMulti(nil, bytes.NewBuffer(wr))
		require.EqualError(t, err, "verify multi: verify error")
	})
}

func TestCommand_DeriveProof(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		cmd := createCmd(t, gomock.NewController(t), withCrypto(&mockcrypto.Crypto{
			DeriveProofValue: []byte("proof"),
		}))

		req, err := json.Marshal(DeriveProofRequest{
			Messages: [][]byte{
				[]byte("test message 1"),
				[]byte("test message 2"),
			},
			Signature:       []byte("signature"),
			Nonce:           []byte("nonce"),
			RevealedIndexes: []int{1},
		})
		require.NoError(t, err)

		wr, err := json.Marshal(WrappedRequest{
			KeyStoreID: "key_store_id",
			KeyID:      "key_id",
			Request:    req,
		})
		require.NoError(t, err)

		var buf bytes.Buffer

		err = cmd.DeriveProof(&buf, bytes.NewBuffer(wr))
		require.NoError(t, err)

		var resp DeriveProofResponse

		err = json.Unmarshal(buf.Bytes(), &resp)
		require.NoError(t, err)
		require.Equal(t, []byte("proof"), resp.Proof)
	})

	t.Run("Fail to derive proof", func(t *testing.T) {
		cmd := createCmd(t, gomock.NewController(t), withCrypto(&mockcrypto.Crypto{
			DeriveProofError: errors.New("derive proof error"),
		}))

		req, err := json.Marshal(DeriveProofRequest{
			Messages: [][]byte{
				[]byte("test message 1"),
				[]byte("test message 2"),
			},
			Signature:       []byte("signature"),
			Nonce:           []byte("nonce"),
			RevealedIndexes: []int{1},
		})
		require.NoError(t, err)

		wr, err := json.Marshal(WrappedRequest{
			KeyStoreID: "key_store_id",
			KeyID:      "key_id",
			Request:    req,
		})
		require.NoError(t, err)

		var buf bytes.Buffer

		err = cmd.DeriveProof(&buf, bytes.NewBuffer(wr))
		require.EqualError(t, err, "derive proof: derive proof error")
	})
}

func TestCommand_VerifyProof(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		cmd := createCmd(t, gomock.NewController(t), withCrypto(&mockcrypto.Crypto{}))

		req, err := json.Marshal(VerifyProofRequest{
			Messages: [][]byte{
				[]byte("test message 1"),
				[]byte("test message 2"),
			},
			Proof: []byte("proof"),
			Nonce: []byte("nonce"),
		})
		require.NoError(t, err)

		wr, err := json.Marshal(WrappedRequest{
			KeyStoreID: "key_store_id",
			KeyID:      "key_id",
			Request:    req,
		})
		require.NoError(t, err)

		err = cmd.VerifyProof(nil, bytes.NewBuffer(wr))
		require.NoError(t, err)
	})

	t.Run("Fail to verify proof", func(t *testing.T) {
		cmd := createCmd(t, gomock.NewController(t), withCrypto(&mockcrypto.Crypto{
			VerifyProofErr: errors.New("verify proof error"),
		}))

		req, err := json.Marshal(VerifyProofRequest{
			Messages: [][]byte{
				[]byte("test message 1"),
				[]byte("test message 2"),
			},
			Proof: []byte("proof"),
			Nonce: []byte("nonce"),
		})
		require.NoError(t, err)

		wr, err := json.Marshal(WrappedRequest{
			KeyStoreID: "key_store_id",
			KeyID:      "key_id",
			Request:    req,
		})
		require.NoError(t, err)

		err = cmd.VerifyProof(nil, bytes.NewBuffer(wr))
		require.EqualError(t, err, "verify proof: verify proof error")
	})
}

func TestCommand_Easy(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		ctrl := gomock.NewController(t)

		cryptoBox := NewMockCryptoBox(ctrl)
		cryptoBox.EXPECT().Easy(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
			Return([]byte("ciphertext"), nil).Times(1)

		creator := NewMockCryptoBoxCreator(ctrl)
		creator.EXPECT().Create(gomock.Any()).Return(cryptoBox, nil).Times(1)

		cmd := createCmd(t, ctrl, withCryptoBoxCreator(creator))

		req, err := json.Marshal(EasyRequest{
			Payload:  []byte("payload"),
			Nonce:    []byte("nonce"),
			TheirPub: []byte("their pub"),
		})
		require.NoError(t, err)

		wr, err := json.Marshal(WrappedRequest{
			KeyStoreID: "key_store_id",
			KeyID:      "key_id",
			Request:    req,
		})
		require.NoError(t, err)

		var buf bytes.Buffer

		err = cmd.Easy(&buf, bytes.NewBuffer(wr))
		require.NoError(t, err)

		var resp EasyResponse

		err = json.Unmarshal(buf.Bytes(), &resp)
		require.NoError(t, err)
		require.Equal(t, []byte("ciphertext"), resp.Ciphertext)
	})

	t.Run("Fail to seal a payload", func(t *testing.T) {
		ctrl := gomock.NewController(t)

		cryptoBox := NewMockCryptoBox(ctrl)
		cryptoBox.EXPECT().Easy(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
			Return(nil, errors.New("easy error")).Times(1)

		creator := NewMockCryptoBoxCreator(ctrl)
		creator.EXPECT().Create(gomock.Any()).Return(cryptoBox, nil).Times(1)

		cmd := createCmd(t, ctrl, withCryptoBoxCreator(creator))

		req, err := json.Marshal(EasyRequest{
			Payload:  []byte("payload"),
			Nonce:    []byte("nonce"),
			TheirPub: []byte("their pub"),
		})
		require.NoError(t, err)

		wr, err := json.Marshal(WrappedRequest{
			KeyStoreID: "key_store_id",
			KeyID:      "key_id",
			Request:    req,
		})
		require.NoError(t, err)

		var buf bytes.Buffer

		err = cmd.Easy(&buf, bytes.NewBuffer(wr))
		require.EqualError(t, err, "easy: easy error")
	})
}

func TestCommand_EasyOpen(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		ctrl := gomock.NewController(t)

		cryptoBox := NewMockCryptoBox(ctrl)
		cryptoBox.EXPECT().EasyOpen(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
			Return([]byte("plaintext"), nil).Times(1)

		creator := NewMockCryptoBoxCreator(ctrl)
		creator.EXPECT().Create(gomock.Any()).Return(cryptoBox, nil).Times(1)

		cmd := createCmd(t, gomock.NewController(t), withCryptoBoxCreator(creator))

		req, err := json.Marshal(EasyOpenRequest{
			Ciphertext: []byte("payload"),
			Nonce:      []byte("nonce"),
			TheirPub:   []byte("their pub"),
			MyPub:      []byte("my pub"),
		})
		require.NoError(t, err)

		wr, err := json.Marshal(WrappedRequest{
			KeyStoreID: "key_store_id",
			KeyID:      "key_id",
			Request:    req,
		})
		require.NoError(t, err)

		var buf bytes.Buffer

		err = cmd.EasyOpen(&buf, bytes.NewBuffer(wr))
		require.NoError(t, err)

		var resp EasyOpenResponse

		err = json.Unmarshal(buf.Bytes(), &resp)
		require.NoError(t, err)
		require.Equal(t, []byte("plaintext"), resp.Plaintext)
	})

	t.Run("Fail to unseal a ciphertext", func(t *testing.T) {
		ctrl := gomock.NewController(t)

		cryptoBox := NewMockCryptoBox(ctrl)
		cryptoBox.EXPECT().EasyOpen(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
			Return(nil, errors.New("easy open error")).Times(1)

		creator := NewMockCryptoBoxCreator(ctrl)
		creator.EXPECT().Create(gomock.Any()).Return(cryptoBox, nil).Times(1)

		cmd := createCmd(t, gomock.NewController(t), withCryptoBoxCreator(creator))

		req, err := json.Marshal(EasyOpenRequest{
			Ciphertext: []byte("payload"),
			Nonce:      []byte("nonce"),
			TheirPub:   []byte("their pub"),
			MyPub:      []byte("my pub"),
		})
		require.NoError(t, err)

		wr, err := json.Marshal(WrappedRequest{
			KeyStoreID: "key_store_id",
			KeyID:      "key_id",
			Request:    req,
		})
		require.NoError(t, err)

		var buf bytes.Buffer

		err = cmd.EasyOpen(&buf, bytes.NewBuffer(wr))
		require.EqualError(t, err, "easy open: easy open error")
	})
}

func TestCommand_SealOpen(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		ctrl := gomock.NewController(t)

		cryptoBox := NewMockCryptoBox(ctrl)
		cryptoBox.EXPECT().SealOpen(gomock.Any(), gomock.Any()).Return([]byte("plaintext"), nil).Times(1)

		creator := NewMockCryptoBoxCreator(ctrl)
		creator.EXPECT().Create(gomock.Any()).Return(cryptoBox, nil).Times(1)

		cmd := createCmd(t, gomock.NewController(t), withCryptoBoxCreator(creator))

		req, err := json.Marshal(SealOpenRequest{
			Ciphertext: []byte("payload"),
			MyPub:      []byte("my pub"),
		})
		require.NoError(t, err)

		wr, err := json.Marshal(WrappedRequest{
			KeyStoreID: "key_store_id",
			KeyID:      "key_id",
			Request:    req,
		})
		require.NoError(t, err)

		var buf bytes.Buffer

		err = cmd.SealOpen(&buf, bytes.NewBuffer(wr))
		require.NoError(t, err)

		var resp SealOpenResponse

		err = json.Unmarshal(buf.Bytes(), &resp)
		require.NoError(t, err)
		require.Equal(t, []byte("plaintext"), resp.Plaintext)
	})

	t.Run("Fail to decrypt a ciphertext", func(t *testing.T) {
		ctrl := gomock.NewController(t)

		cryptoBox := NewMockCryptoBox(ctrl)
		cryptoBox.EXPECT().SealOpen(gomock.Any(), gomock.Any()).Return(nil, errors.New("seal open error")).Times(1)

		creator := NewMockCryptoBoxCreator(ctrl)
		creator.EXPECT().Create(gomock.Any()).Return(cryptoBox, nil).Times(1)

		cmd := createCmd(t, gomock.NewController(t), withCryptoBoxCreator(creator))

		req, err := json.Marshal(SealOpenRequest{
			Ciphertext: []byte("payload"),
			MyPub:      []byte("my pub"),
		})
		require.NoError(t, err)

		wr, err := json.Marshal(WrappedRequest{
			KeyStoreID: "key_store_id",
			KeyID:      "key_id",
			Request:    req,
		})
		require.NoError(t, err)

		var buf bytes.Buffer

		err = cmd.SealOpen(&buf, bytes.NewBuffer(wr))
		require.EqualError(t, err, "seal open: seal open error")
	})
}

func TestCommand_WrapKey(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		cmd := createCmd(t, gomock.NewController(t), withCrypto(&mockcrypto.Crypto{
			WrapValue: &crypto.RecipientWrappedKey{},
		}))

		req, err := json.Marshal(WrapKeyRequest{
			CEK:             []byte("cek"),
			APU:             []byte("apu"),
			APV:             []byte("apv"),
			RecipientPubKey: &crypto.PublicKey{},
			Tag:             []byte("tag"),
		})
		require.NoError(t, err)

		wr, err := json.Marshal(WrappedRequest{
			KeyStoreID: "key_store_id",
			KeyID:      "key_id",
			Request:    req,
		})
		require.NoError(t, err)

		var buf bytes.Buffer

		err = cmd.WrapKey(&buf, bytes.NewBuffer(wr))
		require.NoError(t, err)

		var resp WrapKeyResponse

		err = json.Unmarshal(buf.Bytes(), &resp)
		require.NoError(t, err)
		require.NotNil(t, resp.RecipientWrappedKey)
	})

	t.Run("Fail to wrap a key", func(t *testing.T) {
		cmd := createCmd(t, gomock.NewController(t), withCrypto(&mockcrypto.Crypto{
			WrapError: errors.New("wrap error"),
		}))

		req, err := json.Marshal(WrapKeyRequest{
			CEK:             []byte("cek"),
			APU:             []byte("apu"),
			APV:             []byte("apv"),
			RecipientPubKey: &crypto.PublicKey{},
			Tag:             []byte("tag"),
		})
		require.NoError(t, err)

		wr, err := json.Marshal(WrappedRequest{
			KeyStoreID: "key_store_id",
			KeyID:      "key_id",
			Request:    req,
		})
		require.NoError(t, err)

		var buf bytes.Buffer

		err = cmd.WrapKey(&buf, bytes.NewBuffer(wr))
		require.EqualError(t, err, "wrap key: wrap error")
	})
}

func TestCommand_UnwrapKey(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		cmd := createCmd(t, gomock.NewController(t), withCrypto(&mockcrypto.Crypto{
			UnwrapValue: []byte("key"),
		}))

		req, err := json.Marshal(UnwrapKeyRequest{
			WrappedKey:   crypto.RecipientWrappedKey{},
			SenderPubKey: &crypto.PublicKey{},
			Tag:          []byte("tag"),
		})
		require.NoError(t, err)

		wr, err := json.Marshal(WrappedRequest{
			KeyStoreID: "key_store_id",
			KeyID:      "key_id",
			Request:    req,
		})
		require.NoError(t, err)

		var buf bytes.Buffer

		err = cmd.UnwrapKey(&buf, bytes.NewBuffer(wr))
		require.NoError(t, err)

		var resp UnwrapKeyResponse

		err = json.Unmarshal(buf.Bytes(), &resp)
		require.NoError(t, err)
		require.Equal(t, []byte("key"), resp.Key)
	})

	t.Run("Fail to unwrap a key", func(t *testing.T) {
		cmd := createCmd(t, gomock.NewController(t), withCrypto(&mockcrypto.Crypto{
			UnwrapError: errors.New("unwrap error"),
		}))

		req, err := json.Marshal(UnwrapKeyRequest{
			WrappedKey:   crypto.RecipientWrappedKey{},
			SenderPubKey: &crypto.PublicKey{},
			Tag:          []byte("tag"),
		})
		require.NoError(t, err)

		wr, err := json.Marshal(WrappedRequest{
			KeyStoreID: "key_store_id",
			KeyID:      "key_id",
			Request:    req,
		})
		require.NoError(t, err)

		var buf bytes.Buffer

		err = cmd.UnwrapKey(&buf, bytes.NewBuffer(wr))
		require.EqualError(t, err, "unwrap key: unwrap error")
	})
}

func createCmd(t *testing.T, ctrl *gomock.Controller, opts ...configOption) *Command {
	t.Helper()

	metrics := NewMockMetricsProvider(ctrl)
	metrics.EXPECT().CryptoSignTime(gomock.Any()).AnyTimes()
	metrics.EXPECT().KeyStoreGetKeyTime(gomock.Any()).AnyTimes()
	metrics.EXPECT().KeyStoreResolveTime(gomock.Any()).AnyTimes()

	cr, err := tinkcrypto.New()
	require.NoError(t, err)

	keyStoreData, err := json.Marshal(struct {
		ID         string `json:"id"`
		Controller string `json:"controller"`
	}{
		ID:         "key_store_id",
		Controller: "controller",
	})
	require.NoError(t, err)

	p := mockstorage.NewMockStoreProvider()
	p.Store.Store["key_store_id"] = mockstorage.DBEntry{Value: keyStoreData}

	config := &Config{
		StorageProvider: p,
		KMS:             &mockkms.KeyManager{},
		Crypto:          cr,
		MetricsProvider: metrics,
	}

	for i := range opts {
		opts[i](config)
	}

	creator := NewMockKeyStoreCreator(ctrl)
	creator.EXPECT().Create(gomock.Any(), gomock.Any()).Return(config.KMS, nil).Times(1)

	config.KeyStoreCreator = creator

	cmd, err := New(config)
	require.NoError(t, err)
	require.NotNil(t, cmd)

	return cmd
}

type configOption func(c *Config)

func withStorageProvider(p storage.Provider) configOption {
	return func(c *Config) {
		c.StorageProvider = p
	}
}

func withKeyManager(km kms.KeyManager) configOption {
	return func(c *Config) {
		c.KMS = km
	}
}

func withCrypto(cr crypto.Crypto) configOption {
	return func(c *Config) {
		c.Crypto = cr
	}
}

type cryptoBoxCreator interface {
	Create(km kms.KeyManager) (CryptoBox, error)
}

func withCryptoBoxCreator(creator cryptoBoxCreator) configOption {
	return func(c *Config) {
		c.CryptBoxCreator = creator
	}
}

type shamirSecretLockCreator interface {
	Create(secretShares [][]byte) (secretlock.Service, error)
}

func withShamirSecretLockCreator(creator shamirSecretLockCreator) configOption {
	return func(c *Config) {
		c.ShamirSecretLockCreator = creator
	}
}

type shamirProvider interface {
	FetchSecretShare(subject string) ([]byte, error)
}

func withShamirProvider(provider shamirProvider) configOption {
	return func(c *Config) {
		c.ShamirProvider = provider
	}
}

func createPrivateKey(t *testing.T, kt kms.KeyType) interface{} {
	t.Helper()

	switch kt { //nolint:exhaustive
	case kms.ED25519:
		_, pk, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		return pk
	case kms.ECDSAP256TypeDER, kms.ECDSAP256TypeIEEEP1363:
		pk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		return pk
	case kms.ECDSAP384TypeDER, kms.ECDSAP384TypeIEEEP1363:
		pk, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		require.NoError(t, err)

		return pk
	case kms.ECDSAP521TypeDER, kms.ECDSAP521TypeIEEEP1363:
		pk, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		require.NoError(t, err)

		return pk
	default:
		require.Fail(t, "not supported key type")

		return nil
	}
}

func createRecipientPubKey(t *testing.T) []byte {
	t.Helper()

	kh, err := keyset.NewHandle(ecdh.NISTP256ECDHKWKeyTemplate())
	require.NoError(t, err)

	pub, err := kh.Public()
	require.NoError(t, err)

	buf := new(bytes.Buffer)
	keyWriter := keyio.NewWriter(buf)

	err = pub.WriteWithNoSecrets(keyWriter)
	require.NoError(t, err)

	return buf.Bytes()
}
