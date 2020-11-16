/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package kms_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trustbloc/edge-core/pkg/log/mocklogger"

	mockkeystore "github.com/trustbloc/hub-kms/pkg/internal/mock/keystore"
	mockkms "github.com/trustbloc/hub-kms/pkg/internal/mock/kms"
	kmsservice "github.com/trustbloc/hub-kms/pkg/kms"
	"github.com/trustbloc/hub-kms/pkg/restapi/kms"
	"github.com/trustbloc/hub-kms/pkg/restapi/kms/operation"
)

func TestNew(t *testing.T) {
	controller := kms.New(newConfig())
	require.NotNil(t, controller)
}

func TestGetOperations(t *testing.T) {
	controller := kms.New(newConfig())
	require.NotNil(t, controller)

	ops := controller.GetOperations()

	require.Equal(t, 8, len(ops))
}

func newConfig() *operation.Config {
	return &operation.Config{
		KeystoreService:   mockkeystore.NewMockService(),
		KMSServiceCreator: func(_ *http.Request) (kmsservice.Service, error) { return mockkms.NewMockService(), nil },
		Logger:            &mocklogger.MockLogger{},
		IsSDSUsed:         false,
	}
}
