/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bddutil

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"io"
	"net/http"
)

const (
	keySize = sha256.Size
)

// HTTPDo makes an HTTP request.
func HTTPDo(method, url string, headers map[string]string, body io.Reader,
	tlsConfig *tls.Config) (*http.Response, error) {
	req, err := http.NewRequestWithContext(context.Background(), method, url, body)
	if err != nil {
		return nil, err
	}

	for k, v := range headers {
		req.Header.Add(k, v)
	}

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	return httpClient.Do(req)
}

// GenerateRandomBytes generates an array of 32 random bytes.
func GenerateRandomBytes() []byte {
	buf := make([]byte, keySize)

	_, err := rand.Read(buf)
	if err != nil {
		panic(err)
	}

	return buf
}
