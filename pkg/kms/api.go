/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package kms

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/crypto"

	"github.com/trustbloc/kms/pkg/keystore"
)

// Service manages key stores data and provides support for crypto operations.
type Service interface {
	CreateKeystore(controller, vaultID string) (*KeystoreData, error)
	ResolveKeystore(req *http.Request) (keystore.Keystore, error)
	GetKeystoreData(keystoreID string) (*KeystoreData, error)
	SaveKeystoreData(data *KeystoreData) error
	crypto.Crypto
}

// KeystoreData represents metadata for Keystore.
type KeystoreData struct {
	ID             string          `json:"id"`
	Controller     string          `json:"controller"`
	RecipientKeyID string          `json:"recipientKeyID,omitempty"`
	MACKeyID       string          `json:"macKeyID,omitempty"`
	VaultID        string          `json:"vaultID,omitempty"`
	EDVCapability  json.RawMessage `json:"edvCapability,omitempty"`
	CreatedAt      *time.Time      `json:"createdAt"`
}
