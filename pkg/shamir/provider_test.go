/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package shamir_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/kms/pkg/shamir"
)

func TestProvider_FetchSecretShare_Success(t *testing.T) {
	ctrl := gomock.NewController(t)

	b, err := json.Marshal(struct {
		Secret string `json:"secret"`
	}{
		Secret: base64.StdEncoding.EncodeToString([]byte("secret share")),
	})
	require.NoError(t, err)

	resp := &http.Response{
		StatusCode: http.StatusOK,
		Body:       ioutil.NopCloser(bytes.NewBuffer(b)),
	}

	client := NewMockHTTPClient(ctrl)
	client.EXPECT().Do(gomock.Any()).Return(resp, nil).Times(1)

	provider := shamir.CreateProvider(&shamir.ProviderConfig{
		AuthServerURL:   "https://auth-server",
		AuthServerToken: "test token",
		HTTPClient:      client,
	})
	require.NotNil(t, provider)

	bts, err := provider.FetchSecretShare("test_sub")

	require.NoError(t, err)
	require.Equal(t, "secret share", string(bts))
}

func TestProvider_FetchSecretShare_Failed(t *testing.T) {
	ctrl := gomock.NewController(t)

	b, err := json.Marshal(struct {
		Message string `json:"message"`
	}{
		Message: "bad request",
	})
	require.NoError(t, err)

	resp := &http.Response{
		StatusCode: http.StatusBadRequest,
		Body:       ioutil.NopCloser(bytes.NewBuffer(b)),
	}

	client := NewMockHTTPClient(ctrl)
	client.EXPECT().Do(gomock.Any()).Return(resp, nil).Times(1)

	provider := shamir.CreateProvider(&shamir.ProviderConfig{
		AuthServerURL:   "https://auth-server",
		AuthServerToken: "test token",
		HTTPClient:      client,
	})
	require.NotNil(t, provider)

	bts, err := provider.FetchSecretShare("test_sub")

	require.EqualError(t, err, "bad request")
	require.Nil(t, bts)
}

func TestProvider_FetchSecretShare_HttpFailed(t *testing.T) {
	ctrl := gomock.NewController(t)

	client := NewMockHTTPClient(ctrl)
	client.EXPECT().Do(gomock.Any()).Return(nil, errors.New("simulated error")).Times(1)

	provider := shamir.CreateProvider(&shamir.ProviderConfig{
		AuthServerURL:   "https://auth-server",
		AuthServerToken: "test token",
		HTTPClient:      client,
	})
	require.NotNil(t, provider)

	bts, err := provider.FetchSecretShare("test_sub")

	require.EqualError(t, err, "http do: simulated error")
	require.Nil(t, bts)
}
