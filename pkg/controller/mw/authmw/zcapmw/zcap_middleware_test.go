/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package zcapmw //nolint:testpackage // mocking internal implementation details

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	arieskms "github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/edge-core/pkg/log/mocklogger"
	"github.com/trustbloc/edge-core/pkg/zcapld"

	"github.com/trustbloc/kms/pkg/controller/rest"
)

func TestMiddleware(t *testing.T) {
	t.Run("authz: zcaps", func(t *testing.T) {
		t.Run("protects endpoints", func(t *testing.T) {
			h := &handler{}

			config := newConfig()
			mwFactory := Middleware{Config: config, Action: "createKey"}

			mw := mwFactory.Middleware()(h)
			require.IsType(t, &mwHandler{}, mw)
			(mw).(*mwHandler).routeFunc = func(r *http.Request) namer {
				return &mockNamer{name: r.URL.Path}
			}

			server := httptest.NewServer(mw)
			defer server.Close()

			req, err := http.NewRequest(http.MethodPost, server.URL+rest.KeyPath, http.NoBody) // nolint:noctx // ignore
			require.NoError(t, err)

			response, err := http.DefaultClient.Do(req) // nolint:bodyclose // ignore

			require.NoError(t, err)

			require.Equal(t, http.StatusUnauthorized, response.StatusCode) // we're not sending zcaps

			require.Len(t, h.requestsCaptured, 0) // we're not sending zcaps
		})

		t.Run("badrequest if endpoint is not valid", func(t *testing.T) {
			h := &handler{}

			config := newConfig()
			mwFactory := Middleware{Config: config, Action: ""}

			mw := mwFactory.Middleware()(h)
			require.IsType(t, &mwHandler{}, mw)
			(mw).(*mwHandler).routeFunc = func(r *http.Request) namer {
				return &mockNamer{name: r.URL.Path}
			}

			server := httptest.NewServer(mw)
			defer server.Close()

			response, err := http.Post(server.URL+"/invalid", "", nil) // nolint:bodyclose,noctx // ignore
			require.NoError(t, err)
			require.Equal(t, http.StatusBadRequest, response.StatusCode) // we're not sending zcaps

			require.Len(t, h.requestsCaptured, 0) // we're not sending zcaps
		})

		t.Run("should handle request with Capability-Invocation header", func(t *testing.T) {
			config := newConfig()
			mwFactory := Middleware{Config: config, Action: "createKey"}

			req, err := http.NewRequestWithContext(context.Background(), "", "", http.NoBody)
			require.NoError(t, err)

			req.Header.Add("Capability-Invocation", "zcap")

			require.True(t, mwFactory.Accept(req))
		})
	})
}

func TestZCAPMetrics(t *testing.T) {
	t.Run("CapabilityResolver", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		resolver := NewMockCapabilityResolver(ctrl)
		resolver.EXPECT().Resolve("test uri").Times(1)

		metrics := capabilityResolverMetrics{wrapped: resolver}

		_, err := metrics.Resolve("test uri")
		require.NoError(t, err)
	})

	t.Run("DocumentLoader", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		resolver := NewMockDocumentLoader(ctrl)
		resolver.EXPECT().LoadDocument("test uri").Times(1)

		metrics := documentLoaderMetrics{wrapped: resolver}
		_, err := metrics.LoadDocument("test uri")

		require.NoError(t, err)
	})

	t.Run("CapabilityResolver", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		resolver := NewMockVDRResolver(ctrl)
		resolver.EXPECT().Resolve("test uri").Times(1)

		metrics := vdrResolverMetrics{wrapped: resolver}
		_, err := metrics.Resolve("test uri")

		require.NoError(t, err)
	})
}

type mockNamer struct {
	name string
}

func (m *mockNamer) GetName() string {
	return m.name
}

type handler struct {
	executed         bool
	requestsCaptured []*http.Request
}

func (h *handler) ServeHTTP(_ http.ResponseWriter, r *http.Request) {
	h.executed = true
	h.requestsCaptured = append(h.requestsCaptured, r)
}

func newConfig() *ZCAPConfig {
	config := &ZCAPConfig{
		AuthService:          &mockAuthService{},
		Logger:               &mocklogger.MockLogger{},
		ResourceIDQueryParam: rest.KeyStoreVarName,
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
