/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package shamir

//nolint:lll
//go:generate mockgen -destination gomocks_test.go -self_package mocks -package shamir_test -source=provider.go -mock_names httpClient=MockHTTPClient

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

type httpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// Provider provides shamir secret share.
type Provider interface {
	FetchSecretShare(subject string) ([]byte, error)
}

type provider struct {
	httpClient      httpClient
	authServerURL   string
	authServerToken string
}

// ProviderConfig is a configuration for shamir Provider.
type ProviderConfig struct {
	HTTPClient      httpClient
	AuthServerURL   string
	AuthServerToken string
}

// CreateProvider returns new shamir secret provider.
func CreateProvider(c *ProviderConfig) Provider {
	return &provider{
		httpClient:      c.HTTPClient,
		authServerURL:   c.AuthServerURL,
		authServerToken: c.AuthServerToken,
	}
}

func (p *provider) FetchSecretShare(subject string) ([]byte, error) {
	uri := fmt.Sprintf("%s/secret?sub=%s", p.authServerURL, url.QueryEscape(subject))

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, uri, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("new request: %w", err)
	}

	req.Header.Set("authorization",
		fmt.Sprintf("Bearer %s", base64.StdEncoding.EncodeToString([]byte(p.authServerToken))),
	)

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http do: %w", err)
	}

	defer resp.Body.Close() // nolint: errcheck

	if resp.StatusCode != http.StatusOK {
		return nil, getError(resp.Body)
	}

	var body struct {
		Secret string `json:"secret"`
	}

	if err = json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("decode response body: %w", err)
	}

	secret, err := base64.StdEncoding.DecodeString(body.Secret)
	if err != nil {
		return nil, fmt.Errorf("decode secret: %w", err)
	}

	return secret, nil
}

func getError(reader io.Reader) error {
	body, er := io.ReadAll(reader)
	if er != nil {
		return fmt.Errorf("read body: %w", er)
	}

	var errMsg struct {
		Message string `json:"message"`
	}

	if err := json.Unmarshal(body, &errMsg); err != nil {
		return errors.New(string(body))
	}

	return errors.New(errMsg.Message)
}
