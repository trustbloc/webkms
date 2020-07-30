/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package keystore

import (
	"fmt"
	"time"

	"github.com/google/uuid"
)

const (
	keystoreIDFormat = "urn:uuid:%s"
)

// Service provides functionality for working with a keystore.
type Service interface {
	Create(controller string) (string, error)
}

// Keystore represents vault metadata with a list of associated keys.
type Keystore struct {
	ID         string     `json:"id"`
	Controller string     `json:"controller"`
	KeyIDs     []string   `json:"keyIDs,omitempty"`
	CreatedAt  *time.Time `json:"createdAt"`
}

type service struct {
	repo Repository
}

// NewService returns a new Service instance with the specified repository.
func NewService(repo Repository) Service {
	return &service{repo: repo}
}

// Create creates a new keystore for the given controller (user).
func (s *service) Create(controller string) (string, error) {
	id := fmt.Sprintf(keystoreIDFormat, uuid.New())
	created := time.Now().UTC()

	k := &Keystore{
		ID:         id,
		Controller: controller,
		CreatedAt:  &created,
	}

	err := s.repo.Save(k)
	if err != nil {
		return "", err
	}

	return id, nil
}
