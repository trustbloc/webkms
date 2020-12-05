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
	"strings"
	"sync"
	"time"

	"github.com/bluele/gcache"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock/local/masterlock/hkdf"
	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/edge-core/pkg/sss"
	"github.com/trustbloc/edge-core/pkg/sss/base"

	"github.com/trustbloc/hub-kms/pkg/internal/support"
)

const (
	hubAuthSecretPath = "/secret" // path on Hub Auth to get secret share
)

var (
	cache  gcache.Cache // nolint:gochecknoglobals // this cache instance is global
	doOnce sync.Once    // nolint:gochecknoglobals // this doOnce instance is for the global cache
)

// HubAuthParams defines parameters for HubAuth to get the secret share.
type HubAuthParams struct {
	URL      string
	APIToken string
	Subject  string
}

// Options configures secret split lock dependencies.
type Options struct {
	HTTPClient     support.HTTPClient
	SecretSplitter sss.SecretSplitter
	Logger         log.Logger
}

// Option configures Options.
type Option func(options *Options)

// New returns a new secret split lock instance.
func New(secret []byte, params *HubAuthParams, options ...Option) (secretlock.Service, error) {
	opts := &Options{
		HTTPClient:     http.DefaultClient,
		SecretSplitter: &base.Splitter{},
		Logger:         log.New("hub-kms/secretsplitlock"),
	}

	for i := range options {
		options[i](opts)
	}

	doOnce.Do(func() {
		opts.Logger.Infof("Initializing cache...")
		cache = gcache.New(0).
			LoaderFunc(func(key interface{}) (interface{}, error) {
				uriAndToken := strings.Split(fmt.Sprintf("%s", key), "&")

				return fetchSecretShare(uriAndToken[0], uriAndToken[1], opts.HTTPClient, opts.Logger)
			}).
			Expiration(time.Minute).
			Build()

		opts.Logger.Infof("Initializing cache done.")
	})

	if secret == nil {
		return nil, errors.New("empty secret share")
	}

	uri := fmt.Sprintf("%s%s?sub=%s", params.URL, hubAuthSecretPath, url.QueryEscape(params.Subject))
	token := fmt.Sprintf("Bearer %s", base64.StdEncoding.EncodeToString([]byte(params.APIToken)))

	cachedSecret, err := cache.Get(uri + "&" + token)
	if err != nil {
		return nil, fmt.Errorf("fetch secret share: %w", err)
	}

	otherSecret, ok := cachedSecret.([]byte)
	if !ok {
		return nil, errors.New("fetch secret share from cache is not of type []byte")
	}

	combined, err := opts.SecretSplitter.Combine([][]byte{secret, otherSecret})
	if err != nil {
		return nil, fmt.Errorf("combine secrets: %w", err)
	}

	secLock, err := hkdf.NewMasterLock(string(combined), sha256.New, nil)
	if err != nil {
		return nil, fmt.Errorf("new master lock: %w", err)
	}

	return secLock, nil
}

// WithHTTPClient sets the custom HTTP client.
func WithHTTPClient(c support.HTTPClient) Option {
	return func(o *Options) {
		o.HTTPClient = c
	}
}

// WithSecretSplitter sets the custom secret splitter.
func WithSecretSplitter(s sss.SecretSplitter) Option {
	return func(o *Options) {
		o.SecretSplitter = s
	}
}

// WithLogger sets the custom logger.
func WithLogger(l log.Logger) Option {
	return func(o *Options) {
		o.Logger = l
	}
}

func fetchSecretShare(uri, token string, httpClient support.HTTPClient, logger log.Logger) ([]byte, error) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, uri, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("authorization", token)

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
