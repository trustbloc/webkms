/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package edv

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/google/tink/go/keyset"
	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite/keyio"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
	"github.com/hyperledger/aries-framework-go/pkg/storage/edv"
	"github.com/hyperledger/aries-framework-go/pkg/storage/formattedstore"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/label"
	"go.opentelemetry.io/otel/trace"

	"github.com/trustbloc/hub-kms/pkg/keystore"
)

const (
	edvEndpointPathRoot = "/encrypted-data-vaults"
)

const (
	encAlg  = jose.A256GCM
	encType = "EDVEncryptedDocument"
)

// HeaderSigner computes a signature on the request and returns a header with the signature.
type HeaderSigner interface {
	SignHeader(*http.Request, []byte) (*http.Header, error)
}

// Config defines configuration for the SDS storage provider.
type Config struct {
	KeystoreService keystore.Service
	CryptoService   crypto.Crypto
	TLSConfig       *tls.Config
	EDVServerURL    string
	KeystoreID      string
	HeaderSigner    HeaderSigner
	CacheProvider   storage.Provider
}

var tracer = otel.Tracer("hub-kms/edv") //nolint:gochecknoglobals // ignore

// NewStorageProvider returns a new EDV storage provider instance.
func NewStorageProvider(ctx context.Context, c *Config) (storage.Provider, error) {
	trCtx, span := tracer.Start(ctx, "edv:NewStorageProvider")
	defer span.End()

	startGetKeystore := time.Now()

	k, err := c.KeystoreService.Get(trCtx, c.KeystoreID)
	if err != nil {
		return nil, err
	}

	span.AddEvent("keystore fetched",
		trace.WithAttributes(label.String("duration", time.Since(startGetKeystore).String())))

	startGetKeyHandle := time.Now()

	macKH, err := c.KeystoreService.GetKeyHandle(trCtx, k.MACKeyID)
	if err != nil {
		return nil, err
	}

	span.AddEvent("mac key fetched",
		trace.WithAttributes(label.String("duration", time.Since(startGetKeyHandle).String())))

	macCrypto := edv.NewMACCrypto(macKH, c.CryptoService)

	startCreateProvider := time.Now()

	restProvider, err := c.createRESTProvider(k, macCrypto)
	if err != nil {
		return nil, err
	}

	span.AddEvent("rest provider created",
		trace.WithAttributes(label.String("duration", time.Since(startCreateProvider).String())))

	startCreateFormatter := time.Now()

	encryptedFormatter, err := c.createEncryptedFormatter(trCtx, k, macCrypto)
	if err != nil {
		return nil, err
	}

	span.AddEvent("encrypted formatter created",
		trace.WithAttributes(label.String("duration", time.Since(startCreateFormatter).String())))

	return formattedstore.NewFormattedProvider(restProvider, encryptedFormatter, true,
		formattedstore.WithCacheProvider(c.CacheProvider)), nil
}

func (c *Config) createRESTProvider(k *keystore.Keystore, macCrypto *edv.MACCrypto) (*edv.RESTProvider, error) {
	p, err := edv.NewRESTProvider(
		c.EDVServerURL+edvEndpointPathRoot,
		k.VaultID,
		macCrypto,
		edv.WithTLSConfig(c.TLSConfig),
		edv.WithHeaders(func(req *http.Request) (*http.Header, error) {
			return c.signHeader(req, k.EDVCapability)
		}),
	)
	if err != nil {
		return nil, err
	}

	return p, nil
}

func (c *Config) signHeader(req *http.Request, edvCapability []byte) (*http.Header, error) {
	_, span := tracer.Start(req.Context(), "edv:signHeader")
	defer span.End()

	span.SetAttributes(label.String("http.url", req.URL.String()))

	if len(edvCapability) != 0 {
		return c.HeaderSigner.SignHeader(req, edvCapability)
	}

	return nil, nil
}

func (c *Config) createEncryptedFormatter(ctx context.Context, k *keystore.Keystore,
	macCrypto *edv.MACCrypto) (*edv.EncryptedFormatter, error) {
	trCtx, span := tracer.Start(ctx, "edv:createEncryptedFormatter")
	defer span.End()

	startGetKeyHandle := time.Now()

	recipientKH, err := c.KeystoreService.GetKeyHandle(trCtx, k.RecipientKeyID)
	if err != nil {
		return nil, err
	}

	span.AddEvent("recipient key fetched",
		trace.WithAttributes(label.String("duration", time.Since(startGetKeyHandle).String())))

	startRecPubKey := time.Now()

	pubKey, b, err := recipientPublicKey(recipientKH, k.RecipientKeyID)
	if err != nil {
		return nil, err
	}

	span.AddEvent("recipient public key prepared",
		trace.WithAttributes(label.String("duration", time.Since(startRecPubKey).String())))

	err = json.Unmarshal(b, pubKey)
	if err != nil {
		return nil, fmt.Errorf("unmarshal bytes to a public key: %w", err)
	}

	startNewJWEEncrypt := time.Now()

	encrypter, err := jose.NewJWEEncrypt(encAlg, encType, "", nil, []*crypto.PublicKey{pubKey}, c.CryptoService)
	if err != nil {
		return nil, fmt.Errorf("create JWEEncrypt: %w", err)
	}

	span.AddEvent("jose.NewJWEEncrypt completed",
		trace.WithAttributes(label.String("duration", time.Since(startNewJWEEncrypt).String())))

	keyManager, err := c.KeystoreService.KeyManager()
	if err != nil {
		return nil, err
	}

	decrypter := jose.NewJWEDecrypt(nil, c.CryptoService, keyManager)

	return edv.NewEncryptedFormatter(encrypter, decrypter, macCrypto), nil
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
