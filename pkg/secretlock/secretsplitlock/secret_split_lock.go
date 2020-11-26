/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package secretsplitlock

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/hyperledger/aries-framework-go/pkg/secretlock"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock/local/masterlock/hkdf"
	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/edge-core/pkg/sss"

	"github.com/trustbloc/hub-kms/pkg/internal/support"
)

const (
	secretHeader      = "Hub-Kms-Secret" //nolint:gosec // header with secret A
	userHeader        = "Hub-Kms-User"   // header with a value that represent a user ("subject")
	hubAuthSecretPath = "/secret"        // path on Hub Auth to get secret B
)

// Config defines configuration for the secret split lock.
type Config struct {
	HubAuthURL      string
	HubAuthAPIToken string
	HTTPClient      support.HTTPClient
	SecretSplitter  sss.SecretSplitter
	Logger          log.Logger
}

type secretSplitLock struct {
	hubAuthURL      string
	hubAuthAPIToken string
	httpClient      support.HTTPClient
	secretSplitter  sss.SecretSplitter
	logger          log.Logger
}

// New returns a new secret split lock instance.
func New(config *Config) *secretSplitLock { //nolint:golint // no need for secretSplitLock to be exported
	return &secretSplitLock{
		hubAuthURL:      config.HubAuthURL,
		hubAuthAPIToken: config.HubAuthAPIToken,
		httpClient:      config.HTTPClient,
		secretSplitter:  config.SecretSplitter,
		logger:          config.Logger,
	}
}

// Resolver resolves secret lock for the request.
func (s *secretSplitLock) Resolve(r *http.Request) (secretlock.Service, error) {
	secretA := r.Header.Get(secretHeader)
	if secretA == "" {
		return nil, errors.New("empty secret A")
	}

	decodedSecretA, err := base64.StdEncoding.DecodeString(secretA)
	if err != nil {
		return nil, errors.New("fail to decode secret A")
	}

	sub := r.Header.Get(userHeader)

	secretB, err := s.getSecretB(sub)
	if err != nil {
		return nil, fmt.Errorf("get secret B: %w", err)
	}

	combined, err := s.secretSplitter.Combine([][]byte{decodedSecretA, secretB})
	if err != nil {
		return nil, fmt.Errorf("combine secrets: %w", err)
	}

	secLock, err := hkdf.NewMasterLock(string(combined), sha256.New, nil)
	if err != nil {
		return nil, fmt.Errorf("new master lock: %w", err)
	}

	return secLock, nil
}

func (s *secretSplitLock) getSecretB(sub string) ([]byte, error) {
	uri := fmt.Sprintf("%s/%s?sub=%s", s.hubAuthURL, hubAuthSecretPath, url.QueryEscape(sub))

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, uri, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("authorization",
		fmt.Sprintf("Bearer %s", base64.StdEncoding.EncodeToString([]byte(s.hubAuthAPIToken))),
	)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	defer func() {
		err = resp.Body.Close()
		if err != nil {
			s.logger.Errorf("failed to close response body")
		}
	}()

	var secretResp struct {
		Secret string `json:"secret"`
	}

	err = json.NewDecoder(resp.Body).Decode(&secretResp)
	if err != nil {
		return nil, err
	}

	secret, err := base64.StdEncoding.DecodeString(secretResp.Secret)
	if err != nil {
		return nil, err
	}

	return secret, nil
}
