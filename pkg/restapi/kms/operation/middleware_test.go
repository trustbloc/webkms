/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation // nolint:testpackage // mocking internal implementation details

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	arieskms "github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/edge-core/pkg/log/mocklogger"
	"github.com/trustbloc/edge-core/pkg/zcapld"

	mockkms "github.com/trustbloc/hub-kms/pkg/internal/mock/kms"
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

func TestCapabilityInvocationAction(t *testing.T) {
	t.Run("returns invocation action", func(t *testing.T) {
		testCases := []struct {
			endpoint       string
			expectedAction string
		}{
			{
				endpoint:       keysEndpoint,
				expectedAction: actionCreateKey,
			},
			{
				endpoint:       capabilityEndpoint,
				expectedAction: actionStoreCapability,
			},
			{
				endpoint:       exportEndpoint,
				expectedAction: actionExportKey,
			},
			{
				endpoint:       signEndpoint,
				expectedAction: actionSign,
			},
			{
				endpoint:       verifyEndpoint,
				expectedAction: actionVerify,
			},
			{
				endpoint:       encryptEndpoint,
				expectedAction: actionEncrypt,
			},
			{
				endpoint:       decryptEndpoint,
				expectedAction: actionDecrypt,
			},
			{
				endpoint:       computeMACEndpoint,
				expectedAction: actionComputeMac,
			},
			{
				endpoint:       verifyMACEndpoint,
				expectedAction: actionVerifyMAC,
			},
			{
				endpoint:       wrapEndpoint,
				expectedAction: actionWrap,
			},
			{
				endpoint:       unwrapEndpoint,
				expectedAction: actionUnwrap,
			},
		}

		for i := range testCases {
			test := testCases[i]
			result, err := CapabilityInvocationAction(httptest.NewRequest(http.MethodPost, test.endpoint, nil))
			require.NoError(t, err)
			require.Equal(t, test.expectedAction, result)
		}
	})

	t.Run("fails if request is a relative URL with only one path component", func(t *testing.T) {
		request := httptest.NewRequest(http.MethodPost, "/path", nil)
		request.URL.Path = "path"
		_, err := CapabilityInvocationAction(request)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid path format")
	})

	t.Run("fails if endpoint is not supported", func(t *testing.T) {
		_, err := CapabilityInvocationAction(httptest.NewRequest(http.MethodPost, "/unsupported/path", nil))
		require.Error(t, err)
		require.Contains(t, err.Error(), "unsupported endpoint")
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
	authService authService
	kmsService  kms.Service
	logger      log.Logger
}

func newConfig() *Config {
	cOpts := &options{
		authService: &mockAuthService{},
		kmsService:  &mockkms.MockService{},
		logger:      &mocklogger.MockLogger{},
	}

	config := &Config{
		AuthService: cOpts.authService,
		KMSService:  cOpts.kmsService,
		Logger:      cOpts.logger,
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

func (m *mockAuthService) CreateDIDKey(context.Context) (string, error) {
	if m.createDIDKeyFunc != nil {
		return m.createDIDKeyFunc()
	}

	return "", nil
}

func (m *mockAuthService) NewCapability(context.Context, ...zcapld.CapabilityOption) (*zcapld.Capability, error) {
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
