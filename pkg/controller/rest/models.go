/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package rest

import "time"

// genericError model
//
// swagger:response genericError
type genericError struct { //nolint:unused,deadcode
	// The error message
	//
	// in: body
	Body ErrorResponse
}

// healthCheckReq model
//
// swagger:parameters healthCheckRequest
type healthCheckReq struct{} //nolint:unused,deadcode

// healthCheckResp model
//
// swagger:response healthCheckResp
type healthCheckResp struct { //nolint:unused,deadcode
	// in: body
	Body struct {
		Status      string    `json:"status"`
		CurrentTime time.Time `json:"current_time"`
	}
}

// createKeystoreReq model
//
// swagger:parameters createKeystoreReq
type createKeystoreReq struct { //nolint:unused,deadcode
	// The header with a user (subject) to use for fetching secret share from Auth server
	//
	// Kms-User header
	KmsUser string `json:"Kms-User"`

	// The header with a secret share for shamir secret lock
	//
	// Kms-Secret header
	KmsSecret string `json:"Kms-Secret"`

	// in: body
	Body struct {
		// The keystore's controller
		//
		// Required: true
		Controller string `json:"controller"`
		// An optional vault URL for EDV-backed keystore
		EDVVaultURL string `json:"edv_vault_url"`
		// An optional EDV ZCAPs
		EDVCapability string `json:"edv_capability"`
	}
}

// createKeyReq model
//
// swagger:parameters createKeyReq
type createKeyReqSpec struct { //nolint:unused,deadcode
	// The keystore's ID
	//
	// in: path
	// required: true
	KeystoreID string `json:"keystore_id"`
	// in: body
	Body struct {
		// The key type
		//
		// required: true
		// example:
		KeyType string `json:"key_type"`
	}
}
