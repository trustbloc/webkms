/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package secretsplitlock_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"testing"

	"github.com/hyperledger/aries-framework-go/pkg/secretlock"
	"github.com/rs/xid"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/edge-core/pkg/log/mocklogger"
	"github.com/trustbloc/edge-core/pkg/sss"

	"github.com/trustbloc/hub-kms/pkg/internal/support"
	"github.com/trustbloc/hub-kms/pkg/secretlock/secretsplitlock"
)

func TestNew(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		subPrefix := xid.New().String()
		secretLock, err := newSecretSplitLock(t, subPrefix)

		require.NotNil(t, secretLock)
		require.NoError(t, err)
	})

	t.Run("Error: empty secret share", func(t *testing.T) {
		subPrefix := xid.New().String()
		secretLock, err := newSecretSplitLock(t, subPrefix, withSecret(nil))

		require.Nil(t, secretLock)
		require.Error(t, err)
		require.Contains(t, err.Error(), "empty secret share")
	})
}

/*
	t.Run("Fail to fetch secret share: response error", func(t *testing.T) {
		httpClient := &mockHTTPClient{
			DoFunc: func(req *http.Request) (*http.Response, error) {
				return nil, errors.New("response error")
			},
		}

		subPrefix := xid.New().String()
		t.Logf("Fail to fetch secret share: response error - subPrefix:%s", subPrefix)

		secretLock, err := newSecretSplitLock(t, subPrefix, withHTTPClient(httpClient))

		require.Nil(t, secretLock)
		require.Error(t, err)
		require.Contains(t, err.Error(), "fetch secret share: response error")
	})

	t.Run("Fail to fetch secret share: read body error", func(t *testing.T) {
		subPrefix := xid.New().String()
		t.Logf("Fail to fetch secret share: read body error - subPrefix:%s", subPrefix)

		secretLock, err := newSecretSplitLock(t, subPrefix,
			withResponseBody(ioutil.NopCloser(&failingReader{})))

		require.Nil(t, secretLock)
		require.Error(t, err)
		require.Contains(t, err.Error(), "fetch secret share: read error")
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

		subPrefix := xid.New().String()
		t.Logf("Fail to fetch secret share: read body error when status not OK - subPrefix:%s", subPrefix)

		secretLock, err := newSecretSplitLock(t, subPrefix, withHTTPClient(httpClient))

		require.Nil(t, secretLock)
		require.Error(t, err)
		require.Contains(t, err.Error(), "fetch secret share: read response body:")
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

		subPrefix := xid.New().String()
		t.Logf("Fail to fetch secret share: error message in response - subPrefix:%s", subPrefix)

		secretLock, err := newSecretSplitLock(t, subPrefix, withHTTPClient(httpClient))

		require.Nil(t, secretLock)
		require.Error(t, err)
		require.Contains(t, err.Error(), "fetch secret share: unauthorized")
	})

	t.Run("Fail to fetch secret share: secret decode error", func(t *testing.T) {
		subPrefix := xid.New().String()
		t.Logf("Fail to fetch secret share: secret decode error - subPrefix:%s", subPrefix)

		secretLock, err := newSecretSplitLock(t, subPrefix, withSecretInResponse("!invalid"))

		require.Nil(t, secretLock)
		require.Error(t, err)
		require.Contains(t, err.Error(), "fetch secret share: illegal base64 data")
	})

	t.Run("Error: combine secrets", func(t *testing.T) {
		splitter := &mockSplitter{
			CombineErr: errors.New("combine error"),
		}

		subPrefix := xid.New().String()
		t.Logf("Error: combine secrets - subPrefix:%s", subPrefix)

		secretLock, err := newSecretSplitLock(t, subPrefix, withSecretSplitter(splitter))

		require.Nil(t, secretLock)
		require.Error(t, err)
		require.Contains(t, err.Error(), "combine secrets: combine error")
	})

	t.Run("Error: new master lock: passphrase is empty", func(t *testing.T) {
		splitter := &mockSplitter{
			CombineValue: []byte(""),
		}

		subPrefix := xid.New().String()
		t.Logf("Error: new master lock: passphrase is empty - subPrefix:%s", subPrefix)

		secretLock, err := newSecretSplitLock(t, subPrefix, withSecretSplitter(splitter))

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

		subPrefix := xid.New().String()
		t.Logf("Log when fail to close response body - subPrefix:%s", subPrefix)

		secretLock, err := newSecretSplitLock(t, subPrefix,
			withResponseBody(&failingCloser{bytes.NewReader(b)}),
			withLogger(logger),
		)

		require.NotNil(t, secretLock)
		require.NoError(t, err)
		require.Contains(t, logger.ErrorLogContents, "failed to close response body")
	})
}
*/

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

/*

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
*/

type options struct {
	secret           []byte
	secretInResponse string
	body             io.ReadCloser
	httpClient       support.HTTPClient
	secretSplitter   sss.SecretSplitter
	logger           log.Logger
}

type optionFn func(opts *options)

func newSecretSplitLock(t *testing.T, testID string, opts ...optionFn) (secretlock.Service, error) {
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
		URL:      fmt.Sprintf("https://hub-auth.example.com/%s", testID),
		APIToken: fmt.Sprintf("token%s", testID),
		Subject:  fmt.Sprintf("subject%s", url.QueryEscape(testID)),
	}

	return secretsplitlock.New(cOpts.secret, params,
		secretsplitlock.WithHTTPClient(cOpts.httpClient),
		secretsplitlock.WithSecretSplitter(cOpts.secretSplitter),
		secretsplitlock.WithLogger(cOpts.logger),
	)
}

func withSecret(secret []byte) optionFn {
	return func(o *options) {
		o.secret = secret
	}
}

/*
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
*/
