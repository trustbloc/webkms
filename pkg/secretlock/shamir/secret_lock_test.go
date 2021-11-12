/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package shamir_test

import (
	"testing"

	shamirapi "github.com/hashicorp/vault/shamir"
	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/localkms"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock"
	ariesstorage "github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/kms/pkg/secretlock/shamir"
)

const primaryKeyURI = "local-lock://primarykey"

func Test(t *testing.T) {
	shares, err := shamirapi.Split([]byte("shamir secret"), 2, 2)
	require.NoError(t, err)

	shamirLock, err := shamir.NewLock(shares)
	require.NoError(t, err)

	provider := &mockProvider{
		MockStorageProvider: mem.NewProvider(),
		MockSecretLock:      shamirLock,
	}

	localKMS, err := localkms.New(primaryKeyURI, provider)
	require.NoError(t, err)
	require.NotNil(t, localKMS)

	kid, kh, err := localKMS.Create(kms.AES256GCMType)
	require.NoError(t, err)
	require.NotEmpty(t, kid)
	require.NotNil(t, kh)
}

type mockProvider struct {
	MockStorageProvider ariesstorage.Provider
	MockSecretLock      secretlock.Service
}

func (p *mockProvider) StorageProvider() ariesstorage.Provider {
	return p.MockStorageProvider
}

func (p *mockProvider) SecretLock() secretlock.Service {
	return p.MockSecretLock
}
