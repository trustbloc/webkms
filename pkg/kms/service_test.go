/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package kms_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"testing"
	"time"

	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/mac"
	"github.com/gorilla/mux"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite/ecdh"
	mockcrypto "github.com/hyperledger/aries-framework-go/pkg/mock/crypto"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/mock/kms"
	mocksecretlock "github.com/hyperledger/aries-framework-go/pkg/mock/secretlock"
	mockstorage "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/edge-core/pkg/sss/base"

	"github.com/trustbloc/kms/pkg/kms"
	lock "github.com/trustbloc/kms/pkg/secretlock"
	"github.com/trustbloc/kms/pkg/storage/cache"
)

const (
	testKeystoreID     = "keystoreID"
	testController     = "controller"
	testRecipientKeyID = "recipientKeyID"
	testMACKeyID       = "macKeyID"
	testVaultID        = "vaultID"
)

func TestNewService(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		svc, err := kms.NewService(&kms.Config{
			StorageProvider: mockstorage.NewMockStoreProvider(),
		})

		require.NotNil(t, svc)
		require.NoError(t, err)
	})

	t.Run("Fail to open store", func(t *testing.T) {
		svc, err := kms.NewService(&kms.Config{
			StorageProvider: &mockstorage.MockStoreProvider{
				ErrOpenStoreHandle: errors.New("open store error"),
			},
		})

		require.Nil(t, svc)
		require.Error(t, err)
	})
}

func TestCreateKeystore(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		svc, err := kms.NewService(&kms.Config{
			StorageProvider: mockstorage.NewMockStoreProvider(),
			LocalKMS:        &mockkms.KeyManager{},
		})
		require.NoError(t, err)

		k, err := svc.CreateKeystore(testController, testVaultID)

		require.NotNil(t, k)
		require.NoError(t, err)
	})

	t.Run("Fail to save keystore data", func(t *testing.T) {
		svc, err := kms.NewService(&kms.Config{
			StorageProvider: &mockstorage.MockStoreProvider{
				Store: &mockstorage.MockStore{ErrPut: errors.New("put error")},
			},
			LocalKMS: &mockkms.KeyManager{},
		})
		require.NoError(t, err)

		k, err := svc.CreateKeystore(testController, testVaultID)

		require.Nil(t, k)
		require.Error(t, err)
	})
}

func TestResolveKeystore(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		b, err := json.Marshal(testKeystoreData())
		require.NoError(t, err)

		sp := mockstorage.NewMockStoreProvider()
		sp.Store.Store[testKeystoreID] = mockstorage.DBEntry{Value: b}

		createSecretLockFunc := func(string, lock.Provider, uint64) (secretlock.Service, error) {
			return &mocksecretlock.MockSecretLock{}, nil
		}

		localKMS, err := newMockKeyManager()
		require.NoError(t, err)

		splitter := base.Splitter{}
		secrets, err := splitter.Split([]byte("secret"), 2, 2)
		require.NoError(t, err)

		resp := struct {
			Secret string `json:"secret"`
		}{
			Secret: base64.StdEncoding.EncodeToString(secrets[0]),
		}

		respBytes, err := json.Marshal(resp)
		require.NoError(t, err)

		httpClient := &mockHTTPClient{
			DoFunc: func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       ioutil.NopCloser(bytes.NewReader(respBytes)),
				}, nil
			},
		}

		c := &kms.Config{
			StorageProvider:           sp,
			CacheProvider:             cache.NewProvider(),
			KeyManagerStorageProvider: mockstorage.NewMockStoreProvider(),
			LocalKMS:                  localKMS,
			CryptoService:             &mockcrypto.Crypto{},
			HeaderSigner:              &mockHeaderSigner{},
			PrimaryKeyStorageProvider: mockstorage.NewMockStoreProvider(),
			PrimaryKeyLock:            &mocksecretlock.MockSecretLock{},
			CreateSecretLockFunc:      createSecretLockFunc,
			EDVServerURL:              "edvServerURL",
			HubAuthURL:                "hubAuthURL",
			HTTPClient:                httpClient,
			TLSConfig:                 &tls.Config{MinVersion: tls.VersionTLS12},
		}

		svc, err := kms.NewService(c)
		require.NoError(t, err)

		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "", bytes.NewBuffer([]byte("{}")))
		require.NoError(t, err)

		req = mux.SetURLVars(req, map[string]string{
			"keystoreID": testKeystoreID,
		})

		req.Header.Set("Hub-Kms-Secret", base64.StdEncoding.EncodeToString(secrets[1]))
		req.Header.Set("Hub-Kms-User", "user")

		k, err := svc.ResolveKeystore(req)

		require.NotNil(t, k)
		require.NoError(t, err)
	})
}

func TestGetKeystoreData(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		b, err := json.Marshal(testKeystoreData())
		require.NoError(t, err)

		provider := mockstorage.NewMockStoreProvider()
		provider.Store.Store[testKeystoreID] = mockstorage.DBEntry{Value: b}

		svc, err := kms.NewService(&kms.Config{
			StorageProvider: provider,
			LocalKMS:        &mockkms.KeyManager{},
		})
		require.NoError(t, err)

		keystoreData, err := svc.GetKeystoreData(testKeystoreID)

		require.NotNil(t, keystoreData)
		require.NoError(t, err)
	})

	t.Run("Fail to get keystore data", func(t *testing.T) {
		svc, err := kms.NewService(&kms.Config{
			StorageProvider: &mockstorage.MockStoreProvider{
				Store: &mockstorage.MockStore{ErrGet: errors.New("get error")},
			},
			LocalKMS: &mockkms.KeyManager{},
		})
		require.NoError(t, err)

		keystoreData, err := svc.GetKeystoreData(testKeystoreID)

		require.Nil(t, keystoreData)
		require.Error(t, err)
	})
}

func TestSaveKeystoreData(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		svc, err := kms.NewService(&kms.Config{
			StorageProvider: mockstorage.NewMockStoreProvider(),
			LocalKMS:        &mockkms.KeyManager{},
		})
		require.NoError(t, err)

		err = svc.SaveKeystoreData(testKeystoreData())

		require.NoError(t, err)
	})

	t.Run("Fail to save keystore data", func(t *testing.T) {
		svc, err := kms.NewService(&kms.Config{
			StorageProvider: &mockstorage.MockStoreProvider{
				Store: &mockstorage.MockStore{ErrPut: errors.New("put error")},
			},
			LocalKMS: &mockkms.KeyManager{},
		})
		require.NoError(t, err)

		err = svc.SaveKeystoreData(testKeystoreData())

		require.Error(t, err)
	})
}

func testKeystoreData() *kms.KeystoreData {
	createdAt := time.Now().UTC()

	return &kms.KeystoreData{
		ID:             testKeystoreID,
		Controller:     testController,
		RecipientKeyID: testRecipientKeyID,
		MACKeyID:       testMACKeyID,
		VaultID:        testVaultID,
		CreatedAt:      &createdAt,
	}
}

type mockKeyManager struct {
	recipientKH *keyset.Handle
	macKH       *keyset.Handle
	mockkms.KeyManager
}

func newMockKeyManager() (*mockKeyManager, error) {
	recipientKH, err := keyset.NewHandle(ecdh.NISTP256ECDHKWKeyTemplate())
	if err != nil {
		return nil, fmt.Errorf("new recipient key handle: %w", err)
	}

	macKH, err := keyset.NewHandle(mac.HMACSHA256Tag256KeyTemplate())
	if err != nil {
		return nil, fmt.Errorf("new mac key handle: %w", err)
	}

	return &mockKeyManager{
		recipientKH: recipientKH,
		macKH:       macKH,
		KeyManager:  mockkms.KeyManager{},
	}, nil
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

type mockHTTPClient struct {
	DoFunc func(req *http.Request) (*http.Response, error)
}

func (m *mockHTTPClient) Do(req *http.Request) (*http.Response, error) {
	return m.DoFunc(req)
}

type mockHeaderSigner struct {
	signVal *http.Header
	signErr error
}

func (m *mockHeaderSigner) SignHeader(*http.Request, []byte) (*http.Header, error) {
	return m.signVal, m.signErr
}
