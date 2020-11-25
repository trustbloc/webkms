/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package secretlock

import (
	"net/http"

	"github.com/hyperledger/aries-framework-go/pkg/secretlock"
)

// Resolver resolves secret lock for the request.
type Resolver interface {
	Resolve(req *http.Request) (secretlock.Service, error)
}
