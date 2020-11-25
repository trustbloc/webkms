/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package support

import "net/http"

// HTTPClient represents an HTTP client.
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}
