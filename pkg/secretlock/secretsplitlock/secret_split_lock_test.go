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
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/edge-core/pkg/log/mocklogger"
	"github.com/trustbloc/edge-core/pkg/sss"

	"github.com/trustbloc/hub-kms/pkg/internal/support"
	"github.com/trustbloc/hub-kms/pkg/secretlock/secretsplitlock"
)

const (
	testHubAuthURL      = "https://hub-auth.example.com"
	testHubAuthAPIToken = "token"
)

func TestResolve(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		r := secretsplitlock.New(newConfig(t))

		secLock, err := r.Resolve(buildReq(base64.StdEncoding.EncodeToString([]byte("secretA"))))

		require.NotNil(t, secLock)
		require.NoError(t, err)
	})

	t.Run("Error: empty secret A", func(t *testing.T) {
		r := secretsplitlock.New(newConfig(t))

		secLock, err := r.Resolve(buildReq(""))

		require.Nil(t, secLock)
		require.Error(t, err)
		require.Contains(t, err.Error(), "empty secret A")
	})

	t.Run("Fail to decode secret A", func(t *testing.T) {
		r := secretsplitlock.New(newConfig(t))

		secLock, err := r.Resolve(buildReq("!invalid"))

		require.Nil(t, secLock)
		require.Error(t, err)
		require.Contains(t, err.Error(), "fail to decode secret A")
	})

	t.Run("Fail to get secret B: response error", func(t *testing.T) {
		httpClient := &mockHTTPClient{
			DoFunc: func(req *http.Request) (*http.Response, error) {
				return nil, errors.New("response error")
			},
		}

		r := secretsplitlock.New(newConfig(t, withHTTPClient(httpClient)))

		secLock, err := r.Resolve(buildReq(base64.StdEncoding.EncodeToString([]byte("secretA"))))

		require.Nil(t, secLock)
		require.Error(t, err)
		require.Contains(t, err.Error(), "get secret B: response error")
	})

	t.Run("Fail to get secret B: read body error", func(t *testing.T) {
		r := secretsplitlock.New(newConfig(t, withResponseBody(ioutil.NopCloser(&failingReader{}))))

		secLock, err := r.Resolve(buildReq(base64.StdEncoding.EncodeToString([]byte("secretA"))))

		require.Nil(t, secLock)
		require.Error(t, err)
		require.Contains(t, err.Error(), "get secret B: read error")
	})

	t.Run("Fail to get secret B: secret decode error", func(t *testing.T) {
		r := secretsplitlock.New(newConfig(t, withSecret("test secret")))

		secLock, err := r.Resolve(buildReq(base64.StdEncoding.EncodeToString([]byte("secretA"))))

		require.Nil(t, secLock)
		require.Error(t, err)
		require.Contains(t, err.Error(), "get secret B: illegal base64 data")
	})

	t.Run("Error: combine secrets", func(t *testing.T) {
		splitter := &mockSplitter{
			CombineErr: errors.New("combine error"),
		}

		r := secretsplitlock.New(newConfig(t, withSecretSplitter(splitter)))

		secLock, err := r.Resolve(buildReq(base64.StdEncoding.EncodeToString([]byte("secretA"))))

		require.Nil(t, secLock)
		require.Error(t, err)
		require.Contains(t, err.Error(), "combine secrets: combine error")
	})

	t.Run("Error: new master lock: passphrase is empty", func(t *testing.T) {
		splitter := &mockSplitter{
			CombineValue: []byte(""),
		}

		r := secretsplitlock.New(newConfig(t, withSecretSplitter(splitter)))

		secLock, err := r.Resolve(buildReq(base64.StdEncoding.EncodeToString([]byte("secretA"))))

		require.Nil(t, secLock)
		require.Error(t, err)
		require.Contains(t, err.Error(), "new master lock: passphrase is empty")
	})

	t.Run("Log when fail to close response body", func(t *testing.T) {
		logger := &mocklogger.MockLogger{}

		resp := struct {
			Secret string `json:"secret"`
		}{
			Secret: base64.StdEncoding.EncodeToString([]byte("test secret")),
		}

		b, err := json.Marshal(resp)
		require.NoError(t, err)

		r := secretsplitlock.New(newConfig(t,
			withResponseBody(&failingCloser{bytes.NewReader(b)}),
			withLogger(logger),
		))

		secLock, err := r.Resolve(buildReq(base64.StdEncoding.EncodeToString([]byte("secretA"))))

		require.NotNil(t, secLock)
		require.NoError(t, err)
		require.Contains(t, logger.ErrorLogContents, "failed to close response body")
	})
}

func buildReq(secret string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "https://kms.example.com", nil)

	if secret != "" {
		req.Header.Set("Hub-Kms-Secret", secret)
	}

	req.Header.Set("Hub-Kms-User", "user")

	return req
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
	secret         string
	body           io.ReadCloser
	httpClient     support.HTTPClient
	secretSplitter sss.SecretSplitter
	logger         log.Logger
}

type optionFn func(opts *options)

func newConfig(t *testing.T, opts ...optionFn) *secretsplitlock.Config {
	t.Helper()

	cOpts := &options{
		secret:         base64.StdEncoding.EncodeToString([]byte("test secret")),
		secretSplitter: &mockSplitter{CombineValue: []byte("combined secret")},
		logger:         &mocklogger.MockLogger{},
	}

	for i := range opts {
		opts[i](cOpts)
	}

	if cOpts.httpClient == nil {
		if cOpts.body == nil {
			resp := struct {
				Secret string `json:"secret"`
			}{
				Secret: cOpts.secret,
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

	config := &secretsplitlock.Config{
		HubAuthURL:      testHubAuthURL,
		HubAuthAPIToken: testHubAuthAPIToken,
		HTTPClient:      cOpts.httpClient,
		SecretSplitter:  cOpts.secretSplitter,
		Logger:          cOpts.logger,
	}

	return config
}

func withSecret(secret string) optionFn {
	return func(o *options) {
		o.secret = secret
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
