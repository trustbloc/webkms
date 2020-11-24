/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package zcapld_test

import (
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/google/uuid"
	mockcrypto "github.com/hyperledger/aries-framework-go/pkg/mock/crypto"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/mock/kms"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/edge-core/pkg/storage/mockstore"
	zcapld2 "github.com/trustbloc/edge-core/pkg/zcapld"

	"github.com/trustbloc/hub-kms/pkg/auth/zcapld"
)

func TestNew(t *testing.T) {
	t.Run("error if cannot create store", func(t *testing.T) {
		_, err := zcapld.New(
			&mockkms.KeyManager{},
			&mockcrypto.Crypto{},
			&mockstore.Provider{ErrCreateStore: errors.New("test")},
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to create store")
	})

	t.Run("error if cannot open store", func(t *testing.T) {
		_, err := zcapld.New(
			&mockkms.KeyManager{},
			&mockcrypto.Crypto{},
			&mockstore.Provider{ErrOpenStoreHandle: errors.New("test")},
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
			&mockstore.Provider{},
		)
		require.NoError(t, err)

		didKey, err := svc.CreateDIDKey()
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to create")
		require.Empty(t, didKey)
	})

	t.Run("test success", func(t *testing.T) {
		svc, err := zcapld.New(&mockkms.KeyManager{}, &mockcrypto.Crypto{}, &mockstore.Provider{})
		require.NoError(t, err)

		didKey, err := svc.CreateDIDKey()
		require.NoError(t, err)
		require.NotEmpty(t, didKey)
	})
}

func TestService_SignHeader(t *testing.T) {
	t.Run("test error from sign header", func(t *testing.T) {
		svc, err := zcapld.New(&mockkms.KeyManager{}, &mockcrypto.Crypto{}, &mockstore.Provider{})
		require.NoError(t, err)

		hdr, err := svc.SignHeader(&http.Request{Header: make(map[string][]string)}, []byte("{}"))
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
			&mockstore.Provider{Store: &mockstore.MockStore{Store: make(map[string][]byte)}},
		)
		require.NoError(t, err)
		result, err := svc.NewCapability(
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
			&mockstore.Provider{},
		)
		require.NoError(t, err)
		_, err = svc.NewCapability()
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to create a new signer")
	})

	t.Run("error if cannot create zcap", func(t *testing.T) {
		svc, err := zcapld.New(
			&mockkms.KeyManager{},
			&mockcrypto.Crypto{SignErr: errors.New("test")},
			&mockstore.Provider{},
		)
		require.NoError(t, err)
		_, err = svc.NewCapability()
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to create zcap")
	})

	t.Run("error if cannot save zcap to store", func(t *testing.T) {
		svc, err := zcapld.New(
			&mockkms.KeyManager{},
			&mockcrypto.Crypto{},
			&mockstore.Provider{Store: &mockstore.MockStore{
				Store:  make(map[string][]byte),
				ErrPut: errors.New("test"),
			}},
		)
		require.NoError(t, err)
		_, err = svc.NewCapability()
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to store zcap")
	})
}
