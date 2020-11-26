/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation // nolint:testpackage // mocking internal implementation details

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	arieskms "github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/edge-core/pkg/log/mocklogger"
	"github.com/trustbloc/edge-core/pkg/zcapld"

	mockkeystore "github.com/trustbloc/hub-kms/pkg/internal/mock/keystore"
	mockkms "github.com/trustbloc/hub-kms/pkg/internal/mock/kms"
	"github.com/trustbloc/hub-kms/pkg/keystore"
	"github.com/trustbloc/hub-kms/pkg/kms"
)

func TestMiddleware(t *testing.T) {
	t.Run("returns middleware", func(t *testing.T) {
		o := New(newConfig())
		require.NotEmpty(t, o.ZCAPLDMiddleware(nil))
	})

	t.Run("authz: oauth2", func(t *testing.T) {
		t.Run("protects /keystore endpoint", func(t *testing.T) {
			handler := &handler{}
			result := httptest.NewRecorder()
			mw := New(newConfig()).ZCAPLDMiddleware(handler)
			require.IsType(t, &mwHandler{}, mw)
			(mw).(*mwHandler).routeFunc = mockRouteFunc(&mockNamer{name: keystoresEndpoint})
			mw.ServeHTTP(
				result,
				httptest.NewRequest(http.MethodPost, keystoresEndpoint, nil),
			)
			require.True(t, handler.executed)
		})
	})

	t.Run("authz: zcaps", func(t *testing.T) {
		t.Run("protects endpoints", func(t *testing.T) {
			handler := &handler{}
			mw := New(newConfig()).ZCAPLDMiddleware(handler)
			require.IsType(t, &mwHandler{}, mw)
			(mw).(*mwHandler).routeFunc = func(r *http.Request) namer {
				return &mockNamer{name: r.URL.Path}
			}

			server := httptest.NewServer(mw)
			defer server.Close()

			endpoints := []string{
				keysEndpoint,
				capabilityEndpoint,
				exportEndpoint,
				signEndpoint,
				verifyEndpoint,
				encryptEndpoint,
				decryptEndpoint,
				computeMACEndpoint,
				verifyMACEndpoint,
				wrapEndpoint,
				unwrapEndpoint,
			}

			for _, endpoint := range endpoints {
				_, err := http.Post(server.URL+endpoint, "", nil) // nolint:bodyclose,noctx // ignore
				require.NoError(t, err)
			}

			require.Len(t, handler.requestsCaptured, 0) // we're not sending zcaps
		})

		t.Run("protects endpoints", func(t *testing.T) {
			handler := &handler{}
			mw := New(newConfig()).ZCAPLDMiddleware(handler)
			require.IsType(t, &mwHandler{}, mw)
			(mw).(*mwHandler).routeFunc = func(r *http.Request) namer {
				return &mockNamer{name: r.URL.Path}
			}

			server := httptest.NewServer(mw)
			defer server.Close()

			endpoints := []string{
				keysEndpoint,
				capabilityEndpoint,
				exportEndpoint,
				signEndpoint,
				verifyEndpoint,
				encryptEndpoint,
				decryptEndpoint,
				computeMACEndpoint,
				verifyMACEndpoint,
				wrapEndpoint,
				unwrapEndpoint,
			}

			for _, endpoint := range endpoints {
				response, err := http.Post(server.URL+endpoint, "", nil) // nolint:bodyclose,noctx // ignore
				require.NoError(t, err)
				require.Equal(t, http.StatusUnauthorized, response.StatusCode) // we're not sending zcaps
			}

			require.Len(t, handler.requestsCaptured, 0) // we're not sending zcaps
		})

		t.Run("badrequest if endpoint is not valid", func(t *testing.T) {
			handler := &handler{}
			mw := New(newConfig()).ZCAPLDMiddleware(handler)
			require.IsType(t, &mwHandler{}, mw)
			(mw).(*mwHandler).routeFunc = func(r *http.Request) namer {
				return &mockNamer{name: r.URL.Path}
			}

			server := httptest.NewServer(mw)
			defer server.Close()

			response, err := http.Post(server.URL+"/invalid", "", nil) // nolint:bodyclose,noctx // ignore
			require.NoError(t, err)
			require.Equal(t, http.StatusBadRequest, response.StatusCode) // we're not sending zcaps

			require.Len(t, handler.requestsCaptured, 0) // we're not sending zcaps
		})
	})
}

type mockNamer struct {
	name string
}

func (m *mockNamer) GetName() string {
	return m.name
}

func mockRouteFunc(n namer) func(*http.Request) namer {
	return func(r *http.Request) namer {
		return n
	}
}

type handler struct {
	executed         bool
	requestsCaptured []*http.Request
}

func (h *handler) ServeHTTP(_ http.ResponseWriter, r *http.Request) {
	h.executed = true
	h.requestsCaptured = append(h.requestsCaptured, r)
}

type options struct {
	keystoreService      keystore.Service
	kmsService           kms.Service
	logger               log.Logger
	kmsServiceCreatorErr error
	isEDVUsed            bool
	authService          authService
}

func newConfig() *Config {
	cOpts := &options{
		keystoreService: mockkeystore.NewMockService(),
		kmsService:      mockkms.NewMockService(),
		logger:          &mocklogger.MockLogger{},
		authService:     &mockAuthService{},
	}

	config := &Config{
		KeystoreService:   cOpts.keystoreService,
		KMSServiceCreator: func(_ *http.Request) (kms.Service, error) { return cOpts.kmsService, nil },
		Logger:            cOpts.logger,
		IsEDVUsed:         cOpts.isEDVUsed,
		AuthService:       cOpts.authService,
	}

	if cOpts.kmsServiceCreatorErr != nil {
		config.KMSServiceCreator = func(_ *http.Request) (kms.Service, error) {
			return nil, cOpts.kmsServiceCreatorErr
		}
	}

	return config
}

type mockAuthService struct {
	createDIDKeyFunc func() (string, error)
	newCapabilityVal *zcapld.Capability
	newCapabilityErr error
	keyManager       arieskms.KeyManager
	crpto            crypto.Crypto
	resolveVal       *zcapld.Capability
	resolveErr       error
}

func (m *mockAuthService) CreateDIDKey() (string, error) {
	if m.createDIDKeyFunc != nil {
		return m.createDIDKeyFunc()
	}

	return "", nil
}

func (m *mockAuthService) NewCapability(options ...zcapld.CapabilityOption) (*zcapld.Capability, error) {
	return m.newCapabilityVal, m.newCapabilityErr
}

func (m *mockAuthService) KMS() arieskms.KeyManager {
	return m.keyManager
}

func (m *mockAuthService) Crypto() crypto.Crypto {
	return m.crpto
}

func (m *mockAuthService) Resolve(string) (*zcapld.Capability, error) {
	return m.resolveVal, m.resolveErr
}
