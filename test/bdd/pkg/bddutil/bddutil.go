/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bddutil

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"

	"github.com/trustbloc/edge-core/pkg/log"
)

// HTTPDo makes an HTTP request.
func HTTPDo(method, url, contentType string, body io.Reader, tlsConfig *tls.Config) (*http.Response, error) {
	req, err := http.NewRequestWithContext(context.Background(), method, url, body)
	if err != nil {
		return nil, err
	}

	if contentType != "" {
		req.Header.Add("Content-Type", contentType)
	}

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	return httpClient.Do(req)
}

// CloseResponseBody closes the response body.
func CloseResponseBody(respBody io.Closer, logger log.Logger) {
	err := respBody.Close()
	if err != nil {
		logger.Errorf("Failed to close response body: %s", err.Error())
	}
}
