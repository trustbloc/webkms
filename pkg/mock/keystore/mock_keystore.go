/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package keystore

import "sync"

// MockProvider mocks keystore provider.
type MockProvider struct {
	Store     map[string][]byte
	lock      sync.RWMutex
	CreateErr error
}

// NewMockProvider returns a new instance of mock provider.
func NewMockProvider() *MockProvider {
	return &MockProvider{
		Store: make(map[string][]byte),
	}
}

// CreateStore creates a new keystore with the given name.
func (p MockProvider) CreateStore(name string) error {
	if p.CreateErr != nil {
		return p.CreateErr
	}

	p.lock.Lock()
	p.Store[name] = []byte("")
	p.lock.Unlock()

	return nil
}
