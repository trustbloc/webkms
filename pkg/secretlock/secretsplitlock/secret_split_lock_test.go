/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package secretsplitlock_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"io/ioutil"
	"net/http"
	"testing"

	mockstorage "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/edge-core/pkg/log/mocklogger"
	"github.com/trustbloc/edge-core/pkg/sss"

	"github.com/trustbloc/kms/pkg/internal/support"
	"github.com/trustbloc/kms/pkg/secretlock/secretsplitlock"
)

func TestNew(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		secretLock, err := newSecretSplitLock(t)

		require.NotNil(t, secretLock)
		require.NoError(t, err)
	})

	t.Run("Error: empty secret share", func(t *testing.T) {
		secretLock, err := newSecretSplitLock(t, withSecret(nil))

		require.Nil(t, secretLock)
		require.Error(t, err)
		require.Contains(t, err.Error(), "empty secret share")
	})

	t.Run("Fail to fetch secret share: response error", func(t *testing.T) {
		httpClient := &mockHTTPClient{
			DoFunc: func(req *http.Request) (*http.Response, error) {
				return nil, errors.New("response error")
			},
		}

		secretLock, err := newSecretSplitLock(t, withHTTPClient(httpClient))

		require.Nil(t, secretLock)
		require.Error(t, err)
		require.Contains(t, err.Error(), "get secret share: response error")
	})

	t.Run("Fail to fetch secret share: read body error", func(t *testing.T) {
		secretLock, err := newSecretSplitLock(t, withResponseBody(ioutil.NopCloser(&failingReader{})))

		require.Nil(t, secretLock)
		require.Error(t, err)
		require.Contains(t, err.Error(), "get secret share: read error")
	})

	t.Run("Fail to fetch secret share: read body error when status not OK", func(t *testing.T) {
		httpClient := &mockHTTPClient{
			DoFunc: func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusBadRequest,
					Body:       ioutil.NopCloser(&failingReader{}),
				}, nil
			},
		}

		secretLock, err := newSecretSplitLock(t, withHTTPClient(httpClient))

		require.Nil(t, secretLock)
		require.Error(t, err)
		require.Contains(t, err.Error(), "get secret share: read response body:")
	})

	t.Run("Fail to fetch secret share: error message in response", func(t *testing.T) {
		httpClient := &mockHTTPClient{
			DoFunc: func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusBadRequest,
					Body:       ioutil.NopCloser(bytes.NewReader([]byte("unauthorized"))),
				}, nil
			},
		}

		secretLock, err := newSecretSplitLock(t, withHTTPClient(httpClient))

		require.Nil(t, secretLock)
		require.Error(t, err)
		require.Contains(t, err.Error(), "get secret share: unauthorized")
	})

	t.Run("Fail to fetch secret share: secret decode error", func(t *testing.T) {
		secretLock, err := newSecretSplitLock(t, withSecretInResponse("!invalid"))

		require.Nil(t, secretLock)
		require.Error(t, err)
		require.Contains(t, err.Error(), "get secret share: illegal base64 data")
	})

	t.Run("Error: combine secrets", func(t *testing.T) {
		splitter := &mockSplitter{
			CombineErr: errors.New("combine error"),
		}

		secretLock, err := newSecretSplitLock(t, withSecretSplitter(splitter))

		require.Nil(t, secretLock)
		require.Error(t, err)
		require.Contains(t, err.Error(), "combine secrets: combine error")
	})

	t.Run("Error: new master lock: passphrase is empty", func(t *testing.T) {
		splitter := &mockSplitter{
			CombineValue: []byte(""),
		}

		secretLock, err := newSecretSplitLock(t, withSecretSplitter(splitter))

		require.Nil(t, secretLock)
		require.Error(t, err)
		require.Contains(t, err.Error(), "new master lock: passphrase is empty")
	})

	t.Run("Log when fail to close response body", func(t *testing.T) {
		logger := &mocklogger.MockLogger{}

		resp := struct {
			Secret string `json:"secret"`
		}{
			Secret: base64.StdEncoding.EncodeToString([]byte("other secret share")),
		}

		b, err := json.Marshal(resp)
		require.NoError(t, err)

		secretLock, err := newSecretSplitLock(t,
			withResponseBody(&failingCloser{bytes.NewReader(b)}),
			withLogger(logger),
		)

		require.NotNil(t, secretLock)
		require.NoError(t, err)
		require.Contains(t, logger.ErrorLogContents, "failed to close response body")
	})

	t.Run("Secret share found in the cache", func(t *testing.T) {
		cacheProvider := mockstorage.NewMockStoreProvider()
		cacheProvider.Store.Store["subject"] = mockstorage.DBEntry{
			Value: []byte("other secret share"),
		}

		secretLock, err := newSecretSplitLock(t, withCacheProvider(cacheProvider))

		require.NotNil(t, secretLock)
		require.NoError(t, err)
	})

	t.Run("Cache miss", func(t *testing.T) {
		cacheProvider := mockstorage.NewMockStoreProvider()
		cacheProvider.Store.ErrGet = storage.ErrDataNotFound

		secretLock, err := newSecretSplitLock(t, withCacheProvider(cacheProvider))

		require.NotNil(t, secretLock)
		require.NoError(t, err)
	})

	t.Run("Error: open cache store", func(t *testing.T) {
		cacheProvider := mockstorage.NewMockStoreProvider()
		cacheProvider.ErrOpenStoreHandle = errors.New("open error")

		secretLock, err := newSecretSplitLock(t, withCacheProvider(cacheProvider))

		require.Nil(t, secretLock)
		require.Error(t, err)
		require.Contains(t, err.Error(), "open cache store: open error")
	})

	t.Run("Error: put into cache store", func(t *testing.T) {
		cacheProvider := mockstorage.NewMockStoreProvider()
		cacheProvider.Store.ErrGet = storage.ErrDataNotFound
		cacheProvider.Store.ErrPut = errors.New("put error")

		secretLock, err := newSecretSplitLock(t, withCacheProvider(cacheProvider))

		require.Nil(t, secretLock)
		require.Error(t, err)
		require.Contains(t, err.Error(), "save to cache: put error")
	})

	t.Run("Error: get from cache store", func(t *testing.T) {
		cacheProvider := mockstorage.NewMockStoreProvider()
		cacheProvider.Store.ErrGet = errors.New("get error")

		secretLock, err := newSecretSplitLock(t, withCacheProvider(cacheProvider))

		require.Nil(t, secretLock)
		require.Error(t, err)
		require.Contains(t, err.Error(), "get from cache: get error")
	})

	t.Run("Fetch error after cache miss", func(t *testing.T) {
		cacheProvider := mockstorage.NewMockStoreProvider()
		cacheProvider.Store.ErrGet = storage.ErrDataNotFound

		secretLock, err := newSecretSplitLock(t, withCacheProvider(cacheProvider),
			withResponseBody(ioutil.NopCloser(&failingReader{})))

		require.Nil(t, secretLock)
		require.Error(t, err)
		require.Contains(t, err.Error(), "get secret share: read error")
	})
}

type mockHTTPClient struct {
	DoFunc func(req *http.Request) (*http.Response, error)
}

func (m *mockHTTPClient) Do(req *http.Request) (*http.Response, error) {
	return m.DoFunc(req)
}

type mockSplitter struct {
	CombineValue []byte
	CombineErr   error
}

func (m *mockSplitter) Split(secret []byte, numParts, threshold int) ([][]byte, error) {
	return nil, nil
}

func (m *mockSplitter) Combine(secretParts [][]byte) ([]byte, error) {
	if m.CombineErr != nil {
		return nil, m.CombineErr
	}

	return m.CombineValue, nil
}

type failingReader struct {
}

func (*failingReader) Read(p []byte) (n int, err error) {
	return 0, errors.New("read error")
}

type failingCloser struct {
	io.Reader
}

func (*failingCloser) Close() error {
	return errors.New("close error")
}

type options struct {
	secret           []byte
	secretInResponse string
	body             io.ReadCloser
	httpClient       support.HTTPClient
	secretSplitter   sss.SecretSplitter
	logger           log.Logger
	cacheProvider    storage.Provider
}

type optionFn func(opts *options)

func newSecretSplitLock(t *testing.T, opts ...optionFn) (secretlock.Service, error) {
	t.Helper()

	cOpts := &options{
		secret:           []byte("secret"),
		secretInResponse: base64.StdEncoding.EncodeToString([]byte("other secret share")),
		secretSplitter:   &mockSplitter{CombineValue: []byte("combined secret")},
		logger:           &mocklogger.MockLogger{},
	}

	for i := range opts {
		opts[i](cOpts)
	}

	if cOpts.httpClient == nil {
		if cOpts.body == nil {
			resp := struct {
				Secret string `json:"secret"`
			}{
				Secret: cOpts.secretInResponse,
			}

			b, err := json.Marshal(resp)
			require.NoError(t, err)

			cOpts.body = ioutil.NopCloser(bytes.NewReader(b))
		}

		cOpts.httpClient = &mockHTTPClient{
			DoFunc: func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       cOpts.body,
				}, nil
			},
		}
	}

	params := &secretsplitlock.HubAuthParams{
		URL:      "https://hub-auth.example.com",
		APIToken: "token",
		Subject:  "subject",
	}

	o := []secretsplitlock.Option{
		secretsplitlock.WithHTTPClient(cOpts.httpClient),
		secretsplitlock.WithSecretSplitter(cOpts.secretSplitter),
		secretsplitlock.WithLogger(cOpts.logger),
		secretsplitlock.WithCacheProvider(cOpts.cacheProvider),
	}

	if cOpts.cacheProvider != nil {
		o = append(o, secretsplitlock.WithCacheProvider(cOpts.cacheProvider))
	}

	return secretsplitlock.New(cOpts.secret, params, o...)
}

func withSecret(secret []byte) optionFn {
	return func(o *options) {
		o.secret = secret
	}
}

func withSecretInResponse(secret string) optionFn {
	return func(o *options) {
		o.secretInResponse = secret
	}
}

func withResponseBody(body io.ReadCloser) optionFn {
	return func(o *options) {
		o.body = body
	}
}

func withHTTPClient(client support.HTTPClient) optionFn {
	return func(o *options) {
		o.httpClient = client
	}
}

func withSecretSplitter(splitter sss.SecretSplitter) optionFn {
	return func(o *options) {
		o.secretSplitter = splitter
	}
}

func withLogger(logger log.Logger) optionFn {
	return func(o *options) {
		o.logger = logger
	}
}

func withCacheProvider(cacheProvider storage.Provider) optionFn {
	return func(o *options) {
		o.cacheProvider = cacheProvider
	}
}
