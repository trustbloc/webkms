/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package sds

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"

	"github.com/google/tink/go/keyset"
	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite/keyio"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
	"github.com/hyperledger/aries-framework-go/pkg/storage/edv"

	"github.com/trustbloc/hub-kms/pkg/keystore"
)

const (
	edvEndpointPathRoot = "/encrypted-data-vaults"
)

const (
	encAlg  = jose.A256GCM
	encType = "EDVEncryptedDocument"
)

// Config defines configuration for the SDS storage provider.
type Config struct {
	KeystoreService keystore.Service
	CryptoService   crypto.Crypto
	TLSConfig       *tls.Config
	SDSServerURL    string
	KeystoreID      string
}

// NewStorageProvider returns a new SDS storage provider instance.
func NewStorageProvider(c *Config) (storage.Provider, error) {
	k, err := c.KeystoreService.Get(c.KeystoreID)
	if err != nil {
		return nil, err
	}

	edvRESTProvider, err := c.createEDVRESTProvider(k)
	if err != nil {
		return nil, err
	}

	encryptedFormatter, err := c.createEncryptedFormatter(k)
	if err != nil {
		return nil, err
	}

	return storage.NewFormattedProvider(edvRESTProvider, encryptedFormatter), nil
}

func (c *Config) createEDVRESTProvider(k *keystore.Keystore) (*edv.RESTProvider, error) {
	macKH, err := c.KeystoreService.GetKeyHandle(k.MACKeyID)
	if err != nil {
		return nil, err
	}

	macCrypto := edv.NewMACCrypto(macKH, c.CryptoService)

	edvServerURL := c.SDSServerURL + edvEndpointPathRoot

	p, err := edv.NewRESTProvider(edvServerURL, k.OperationalVaultID, macCrypto, edv.WithTLSConfig(c.TLSConfig))
	if err != nil {
		return nil, err
	}

	return p, nil
}

func (c *Config) createEncryptedFormatter(k *keystore.Keystore) (*edv.EncryptedFormatter, error) {
	recipientKH, err := c.KeystoreService.GetKeyHandle(k.RecipientKeyID)
	if err != nil {
		return nil, err
	}

	pubKey, b, err := recipientPublicKey(recipientKH, k.RecipientKeyID)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(b, pubKey)
	if err != nil {
		return nil, fmt.Errorf("unmarshal bytes to a public key: %w", err)
	}

	encrypter, err := jose.NewJWEEncrypt(encAlg, encType, "", nil, []*crypto.PublicKey{pubKey}, c.CryptoService)
	if err != nil {
		return nil, fmt.Errorf("create JWEEncrypt: %w", err)
	}

	keyManager, err := c.KeystoreService.KeyManager()
	if err != nil {
		return nil, err
	}

	decrypter := jose.NewJWEDecrypt(nil, c.CryptoService, keyManager)

	return edv.NewEncryptedFormatter(encrypter, decrypter), nil
}

func recipientPublicKey(kh interface{}, kID string) (*crypto.PublicKey, []byte, error) {
	pubKH, err := kh.(*keyset.Handle).Public()
	if err != nil {
		return nil, nil, fmt.Errorf("get public KH from recipient KH: %w", err)
	}

	buf := new(bytes.Buffer)
	keyWriter := keyio.NewWriter(buf)

	err = pubKH.WriteWithNoSecrets(keyWriter)
	if err != nil {
		return nil, nil, fmt.Errorf("write keyset: %w", err)
	}

	pubKey := new(crypto.PublicKey)
	pubKey.KID = kID

	return pubKey, buf.Bytes(), nil
}
