/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cache

//go:generate mockgen -destination gomocks_test.go -package cache_test . Cache,KeyManager

import (
	"fmt"
	"time"

	arieskms "github.com/hyperledger/aries-framework-go/pkg/kms"
)

const (
	keyNamespace         = "kms_key"
	keyPubBytesNamespace = "kms_key_pub_bytes"
	cacheKeyFormat       = "%s_%s"
	cacheItemCost        = 1
)

// Cache represents caching functionality. Concrete implementation is expected to be thread-safe,
// and clean up items when ttl is expired.
type Cache interface {
	Get(key interface{}) (interface{}, bool)
	SetWithTTL(key, value interface{}, cost int64, ttl time.Duration) bool
	Del(key interface{})
}

// Provider provides cache support for sensitive data like unencrypted keys from KeyManager, and Shamir secret shares.
type Provider struct {
	Cache Cache
}

// KeyManager is an alias for arieskms.KeyManager.
type KeyManager = arieskms.KeyManager

type wrappedKMS struct {
	kms   KeyManager
	cache Cache
	ttl   time.Duration
}

// WrapKMS adds caching support to the underlying KeyManager.
func (p *Provider) WrapKMS(kms KeyManager, cacheTTL time.Duration) (KeyManager, error) {
	// TODO: Maybe it is also a good idea to limit the max value for cacheTTL here.
	if cacheTTL <= 0 {
		return nil, fmt.Errorf("cacheTTL cant be less or equal to zero")
	}

	return &wrappedKMS{
		kms:   kms,
		cache: p.Cache,
		ttl:   cacheTTL,
	}, nil
}

func (w *wrappedKMS) Create(kt arieskms.KeyType, opts ...arieskms.KeyOpts) (string, interface{}, error) {
	keyID, kh, err := w.kms.Create(kt, opts...)
	if err != nil {
		return "", nil, err
	}

	w.addKeyHandleToCache(keyID, kh)

	return keyID, kh, nil
}

func (w *wrappedKMS) Get(keyID string) (interface{}, error) {
	kh, ok := w.cache.Get(keyCacheItemID(keyID))
	if ok {
		return kh, nil
	}

	kh, err := w.kms.Get(keyID)
	if err != nil {
		return nil, err
	}

	w.addKeyHandleToCache(keyID, kh)

	return kh, nil
}

func (w *wrappedKMS) Rotate(kt arieskms.KeyType, keyID string, opts ...arieskms.KeyOpts) (string, interface{}, error) {
	return w.kms.Rotate(kt, keyID, opts...)
}

func (w *wrappedKMS) ExportPubKeyBytes(keyID string) ([]byte, arieskms.KeyType, error) {
	v, ok := w.cache.Get(pubBytesCacheItemID(keyID))
	if ok {
		return v.([]byte), "", nil
	}

	pubKeyBytes, kt, err := w.kms.ExportPubKeyBytes(keyID)
	if err != nil {
		return nil, "", err
	}

	w.addPubBytesToCache(keyID, pubKeyBytes)

	return pubKeyBytes, kt, nil
}

func (w *wrappedKMS) CreateAndExportPubKeyBytes(kt arieskms.KeyType, opts ...arieskms.KeyOpts) (string, []byte, error) {
	keyID, pubKeyBytes, err := w.kms.CreateAndExportPubKeyBytes(kt, opts...)
	if err != nil {
		return "", nil, err
	}

	w.addPubBytesToCache(keyID, pubKeyBytes)

	return keyID, pubKeyBytes, nil
}

func (w *wrappedKMS) PubKeyBytesToHandle(pubKey []byte, kt arieskms.KeyType,
	opts ...arieskms.KeyOpts) (interface{}, error) {
	return w.kms.PubKeyBytesToHandle(pubKey, kt, opts...)
}

func (w *wrappedKMS) ImportPrivateKey(privateKey interface{}, kt arieskms.KeyType,
	opts ...arieskms.PrivateKeyOpts,
) (string, interface{}, error) {
	return w.kms.ImportPrivateKey(privateKey, kt, opts...)
}

func (w *wrappedKMS) addKeyHandleToCache(id string, kh interface{}) {
	w.cache.SetWithTTL(keyCacheItemID(id), kh, cacheItemCost, w.ttl)
}

func keyCacheItemID(id string) string {
	return fmt.Sprintf(cacheKeyFormat, keyNamespace, id)
}

func (w *wrappedKMS) addPubBytesToCache(id string, pubKeyBytes []byte) {
	w.cache.SetWithTTL(pubBytesCacheItemID(id), pubKeyBytes, cacheItemCost, w.ttl)
}

func pubBytesCacheItemID(id string) string {
	return fmt.Sprintf(cacheKeyFormat, keyPubBytesNamespace, id)
}
