/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package zcapld_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/google/uuid"
	mockcrypto "github.com/hyperledger/aries-framework-go/pkg/mock/crypto"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/mock/kms"
	mockstorage "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	"github.com/stretchr/testify/require"
	zcapld2 "github.com/trustbloc/edge-core/pkg/zcapld"
	"golang.org/x/net/context"

	"github.com/trustbloc/hub-kms/pkg/auth/zcapld"
)

func TestNew(t *testing.T) {
	t.Run("error if cannot open store", func(t *testing.T) {
		_, err := zcapld.New(
			&mockkms.KeyManager{},
			&mockcrypto.Crypto{},
			&mockstorage.MockStoreProvider{ErrOpenStoreHandle: errors.New("test")},
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to open store")
	})
}

func TestService_CreateDIDKey(t *testing.T) {
	t.Run("test error from create did key", func(t *testing.T) {
		svc, err := zcapld.New(
			&mockkms.KeyManager{CreateKeyErr: fmt.Errorf("failed to create")},
			&mockcrypto.Crypto{},
			&mockstorage.MockStoreProvider{},
		)
		require.NoError(t, err)

		didKey, err := svc.CreateDIDKey(context.Background())
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to create")
		require.Empty(t, didKey)
	})

	t.Run("test success", func(t *testing.T) {
		svc, err := zcapld.New(&mockkms.KeyManager{}, &mockcrypto.Crypto{}, &mockstorage.MockStoreProvider{})
		require.NoError(t, err)

		didKey, err := svc.CreateDIDKey(context.Background())
		require.NoError(t, err)
		require.NotEmpty(t, didKey)
	})
}

func TestService_SignHeader(t *testing.T) {
	t.Run("test error from parse capability", func(t *testing.T) {
		svc, err := zcapld.New(&mockkms.KeyManager{}, &mockcrypto.Crypto{}, &mockstorage.MockStoreProvider{})
		require.NoError(t, err)

		hdr, err := svc.SignHeader(&http.Request{Header: make(map[string][]string)}, []byte(""))
		require.Error(t, err)
		require.Nil(t, hdr)
	})

	t.Run("test error from sign header", func(t *testing.T) {
		svc, err := zcapld.New(&mockkms.KeyManager{}, &mockcrypto.Crypto{}, &mockstorage.MockStoreProvider{})
		require.NoError(t, err)

		hdr, err := svc.SignHeader(&http.Request{
			Header: make(map[string][]string),
			Method: http.MethodGet,
		}, []byte("{}"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "error creating signature")
		require.Nil(t, hdr)
	})
}

func TestService_NewCapability(t *testing.T) {
	t.Run("returns new zcap", func(t *testing.T) {
		invoker := uuid.New().String()
		target := uuid.New().String()
		allowedAction := []string{uuid.New().String(), uuid.New().String()}
		svc, err := zcapld.New(
			&mockkms.KeyManager{},
			&mockcrypto.Crypto{},
			&mockstorage.MockStoreProvider{Store: &mockstorage.MockStore{Store: make(map[string][]byte)}},
		)
		require.NoError(t, err)
		result, err := svc.NewCapability(
			context.Background(),
			zcapld2.WithInvoker(invoker),
			zcapld2.WithInvocationTarget(target, "urn:kms:keystore"),
			zcapld2.WithAllowedActions(allowedAction...),
		)
		require.NoError(t, err)
		require.Equal(t, invoker, result.Invoker)
		require.Equal(t, target, result.InvocationTarget.ID)
		require.Equal(t, result.AllowedAction, allowedAction)
	})

	t.Run("error if cannot create new crypto signer", func(t *testing.T) {
		svc, err := zcapld.New(
			&mockkms.KeyManager{CreateKeyErr: errors.New("test")},
			&mockcrypto.Crypto{},
			&mockstorage.MockStoreProvider{},
		)
		require.NoError(t, err)
		_, err = svc.NewCapability(context.Background())
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to create a new signer")
	})

	t.Run("error if cannot create zcap", func(t *testing.T) {
		svc, err := zcapld.New(
			&mockkms.KeyManager{},
			&mockcrypto.Crypto{SignErr: errors.New("test")},
			&mockstorage.MockStoreProvider{},
		)
		require.NoError(t, err)
		_, err = svc.NewCapability(context.Background())
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to create zcap")
	})

	t.Run("error if cannot save zcap to store", func(t *testing.T) {
		svc, err := zcapld.New(
			&mockkms.KeyManager{},
			&mockcrypto.Crypto{},
			&mockstorage.MockStoreProvider{Store: &mockstorage.MockStore{
				Store:  make(map[string][]byte),
				ErrPut: errors.New("test"),
			}},
		)
		require.NoError(t, err)
		_, err = svc.NewCapability(context.Background())
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to store zcap")
	})
}

func TestService_Resolve(t *testing.T) {
	t.Run("resolves zcap from store", func(t *testing.T) {
		store := &mockstorage.MockStore{
			Store: make(map[string][]byte),
		}
		svc, err := zcapld.New(
			&mockkms.KeyManager{},
			&mockcrypto.Crypto{},
			&mockstorage.MockStoreProvider{Store: store},
		)
		require.NoError(t, err)

		zcap, err := svc.NewCapability(context.Background())
		require.NotNil(t, zcap)
		require.NoError(t, err)

		b, err := json.Marshal(zcap)
		require.NotNil(t, b)
		require.NoError(t, err)
		store.Store["uri"] = b

		resolved, err := svc.Resolve("uri")

		require.NotNil(t, resolved)
		require.NoError(t, err)
	})

	t.Run("error if cannot get zcap from store", func(t *testing.T) {
		svc, err := zcapld.New(
			&mockkms.KeyManager{},
			&mockcrypto.Crypto{},
			&mockstorage.MockStoreProvider{Store: &mockstorage.MockStore{
				Store:  make(map[string][]byte),
				ErrGet: errors.New("get error"),
			}},
		)
		require.NoError(t, err)

		resolved, err := svc.Resolve("uri")

		require.Nil(t, resolved)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to fetch zcap from storage: get error")
	})
}
