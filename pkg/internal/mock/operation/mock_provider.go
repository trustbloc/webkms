/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"net/http"

	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/edge-core/pkg/log/mocklogger"

	mockkeystore "github.com/trustbloc/hub-kms/pkg/internal/mock/keystore"
	mockkms "github.com/trustbloc/hub-kms/pkg/internal/mock/kms"
	"github.com/trustbloc/hub-kms/pkg/keystore"
	"github.com/trustbloc/hub-kms/pkg/kms"
)

// MockProvider is a mock Operation Provider.
type MockProvider struct {
	MockKeystoreService  *mockkeystore.MockService
	MockKMSService       *mockkms.MockService
	MockLogger           *mocklogger.MockLogger
	KMSServiceCreatorErr error
}

// NewMockProvider returns a new mock Operation Provider.
func NewMockProvider() *MockProvider {
	return &MockProvider{
		MockKeystoreService: mockkeystore.NewMockService(),
		MockKMSService:      mockkms.NewMockService(),
		MockLogger:          &mocklogger.MockLogger{},
	}
}

// KeystoreService returns a mock Keystore service.
func (p MockProvider) KeystoreService() keystore.Service {
	return p.MockKeystoreService
}

// KMSServiceCreator returns a func to create a mock KMS service.
func (p MockProvider) KMSServiceCreator() func(req *http.Request) (kms.Service, error) {
	return func(_ *http.Request) (kms.Service, error) {
		if p.KMSServiceCreatorErr != nil {
			return nil, p.KMSServiceCreatorErr
		}

		return p.MockKMSService, nil
	}
}

// Logger gets a mock of the Logger instance.
func (p MockProvider) Logger() log.Logger {
	return p.MockLogger
}
