/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package keystore

import (
	"time"

	arieskms "github.com/hyperledger/aries-framework-go/pkg/kms"
)

// Keystore represents user's keystore with a list of associated keys and metadata.
type Keystore struct {
	ID                string     `json:"id"`
	Controller        string     `json:"controller"`
	DelegateKeyID     string     `json:"delegateKeyID,omitempty"`
	RecipientKeyID    string     `json:"recipientKeyID,omitempty"`
	CreatedAt         *time.Time `json:"createdAt"`
	OperationalKeyIDs []string   `json:"operationalKeyIDs,omitempty"`
}

// Options configures Keystore during creation.
type Options struct {
	ID               string
	Controller       string
	DelegateKeyType  arieskms.KeyType
	RecipientKeyType arieskms.KeyType
	CreatedAt        *time.Time
}

// Option configures Options.
type Option func(options *Options)

// WithID sets ID of Keystore.
func WithID(id string) Option {
	return func(o *Options) {
		o.ID = id
	}
}

// WithController sets the controller of Keystore.
func WithController(c string) Option {
	return func(o *Options) {
		o.Controller = c
	}
}

// WithDelegateKeyType sets a type of the delegate key.
// Key is not created if type is not specified.
func WithDelegateKeyType(k arieskms.KeyType) Option {
	return func(o *Options) {
		o.DelegateKeyType = k
	}
}

// WithRecipientKeyType sets a type of the recipient key.
// Key is not created if type is not specified.
func WithRecipientKeyType(k arieskms.KeyType) Option {
	return func(o *Options) {
		o.RecipientKeyType = k
	}
}

// WithCreatedAt sets the creation time of Keystore.
func WithCreatedAt(t *time.Time) Option {
	return func(o *Options) {
		o.CreatedAt = t
	}
}
