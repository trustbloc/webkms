/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package keystore_test

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	mock "github.com/trustbloc/hub-kms/pkg/internal/mock/keystore"
	"github.com/trustbloc/hub-kms/pkg/keystore"
)

const (
	testController = "controller"
)

func TestNewService(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		srv := keystore.NewService(mock.NewMockRepository())
		require.NotNil(t, srv)
	})
}

func TestCreate(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		srv := keystore.NewService(mock.NewMockRepository())
		require.NotNil(t, srv)

		keystoreID, err := srv.Create(testController)
		require.NotEmpty(t, keystoreID)
		require.NoError(t, err)
	})

	t.Run("Error: repository save", func(t *testing.T) {
		repo := mock.NewMockRepository()
		repo.ErrSave = errors.New("save error")

		srv := keystore.NewService(repo)
		require.NotNil(t, srv)

		keystoreID, err := srv.Create(testController)
		require.Empty(t, keystoreID)
		require.Error(t, err)
	})
}
