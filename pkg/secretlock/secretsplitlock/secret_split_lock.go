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
	"io/ioutil"
	"net/http"
	"net/url"

	"github.com/hyperledger/aries-framework-go/pkg/secretlock"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock/local/masterlock/hkdf"
	ariesstorage "github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/edge-core/pkg/sss"
	"github.com/trustbloc/edge-core/pkg/sss/base"

	"github.com/trustbloc/kms/pkg/internal/support"
)

const (
	hubAuthSecretPath = "/secret" // path on Hub Auth to get secret share
	cacheStore        = "secretsplitlock"
)

// HubAuthParams defines parameters for HubAuth to get the secret share.
type HubAuthParams struct {
	URL      string
	APIToken string
	Subject  string
}

// Options configures secret split lock dependencies.
type Options struct {
	httpClient     support.HTTPClient
	secretSplitter sss.SecretSplitter
	logger         log.Logger
	cacheProvider  ariesstorage.Provider
}

// Option configures Options.
type Option func(options *Options)

// New returns a new secret split lock instance.
func New(secret []byte, params *HubAuthParams, options ...Option) (secretlock.Service, error) {
	opts := &Options{
		httpClient:     http.DefaultClient,
		secretSplitter: &base.Splitter{},
		logger:         log.New("kms/secretsplitlock"),
	}

	for i := range options {
		options[i](opts)
	}

	return createSecretSplitLock(secret, params, opts)
}

// WithHTTPClient sets the custom HTTP client.
func WithHTTPClient(c support.HTTPClient) Option {
	return func(o *Options) {
		o.httpClient = c
	}
}

// WithSecretSplitter sets the custom secret splitter.
func WithSecretSplitter(s sss.SecretSplitter) Option {
	return func(o *Options) {
		o.secretSplitter = s
	}
}

// WithLogger sets the custom logger.
func WithLogger(l log.Logger) Option {
	return func(o *Options) {
		o.logger = l
	}
}

// WithCacheProvider sets a cache provider.
func WithCacheProvider(p ariesstorage.Provider) Option {
	return func(o *Options) {
		o.cacheProvider = p
	}
}

func createSecretSplitLock(secret []byte, params *HubAuthParams, opts *Options) (secretlock.Service, error) {
	if secret == nil {
		return nil, errors.New("empty secret share")
	}

	fetchFunc := func() ([]byte, error) {
		return fetch(params.URL, params.APIToken, params.Subject, opts.httpClient, opts.logger)
	}

	share, err := getSecretShare(params.Subject, opts.cacheProvider, fetchFunc)
	if err != nil {
		return nil, fmt.Errorf("get secret share: %w", err)
	}

	combined, err := opts.secretSplitter.Combine([][]byte{secret, share})
	if err != nil {
		return nil, fmt.Errorf("combine secrets: %w", err)
	}

	secLock, err := hkdf.NewMasterLock(string(combined), sha256.New, nil)
	if err != nil {
		return nil, fmt.Errorf("new master lock: %w", err)
	}

	return secLock, nil
}

func getSecretShare(cacheKey string, cacheProvider ariesstorage.Provider,
	fetchFunc func() ([]byte, error)) ([]byte, error) {
	if cacheProvider == nil {
		return fetchFunc()
	}

	cache, err := cacheProvider.OpenStore(cacheStore)
	if err != nil {
		return nil, fmt.Errorf("open cache store: %w", err)
	}

	cachedSecret, getErr := cache.Get(cacheKey)
	if getErr == nil {
		return cachedSecret, nil
	}

	if errors.Is(getErr, ariesstorage.ErrDataNotFound) {
		secret, fetchErr := fetchFunc()
		if fetchErr != nil {
			return nil, fetchErr
		}

		putErr := cache.Put(cacheKey, secret)
		if putErr != nil {
			return nil, fmt.Errorf("save to cache: %w", putErr)
		}

		return secret, nil
	}

	return nil, fmt.Errorf("get from cache: %w", getErr)
}

func fetch(serverURL, apiToken, subject string, httpClient support.HTTPClient, logger log.Logger) ([]byte, error) {
	uri := fmt.Sprintf("%s%s?sub=%s", serverURL, hubAuthSecretPath, url.QueryEscape(subject))

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, uri, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("authorization",
		fmt.Sprintf("Bearer %s", base64.StdEncoding.EncodeToString([]byte(apiToken))),
	)

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	defer func() {
		err = resp.Body.Close()
		if err != nil {
			logger.Errorf("failed to close response body")
		}
	}()

	if resp.StatusCode != http.StatusOK {
		body, errRead := ioutil.ReadAll(resp.Body)
		if errRead != nil {
			return nil, fmt.Errorf("read response body: %s", errRead)
		}

		return nil, fmt.Errorf("%s", body)
	}

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
