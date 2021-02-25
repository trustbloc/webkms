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
	"github.com/hyperledger/aries-framework-go/component/storage/edv"
	"github.com/hyperledger/aries-framework-go/component/storageutil/cachedstore"
	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite/keyio"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/label"
	"go.opentelemetry.io/otel/trace"
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

// Config defines configuration for the EDV storage provider.
type Config struct {
	KeyManager     kms.KeyManager
	CryptoService  crypto.Crypto
	HeaderSigner   HeaderSigner
	CacheProvider  storage.Provider
	TLSConfig      *tls.Config
	EDVCapability  json.RawMessage
	EDVServerURL   string
	VaultID        string
	RecipientKeyID string
	MACKeyID       string
}

var tracer = otel.Tracer("kms/edv") //nolint:gochecknoglobals // ignore

// NewStorageProvider returns a new EDV storage provider instance.
func NewStorageProvider(ctx context.Context, c *Config) (storage.Provider, error) {
	trCtx, span := tracer.Start(ctx, "edv:NewStorageProvider")
	defer span.End()

	startGetMACKeyHandle := time.Now()

	macKH, err := c.KeyManager.Get(c.MACKeyID)
	if err != nil {
		return nil, err
	}

	span.AddEvent("mac key fetched",
		trace.WithAttributes(label.String("duration", time.Since(startGetMACKeyHandle).String())))

	macCrypto := edv.NewMACCrypto(macKH, c.CryptoService)

	startCreateProvider := time.Now()

	span.AddEvent("rest provider created",
		trace.WithAttributes(label.String("duration", time.Since(startCreateProvider).String())))

	startCreateFormatter := time.Now()

	encryptedFormatter, err := c.createEncryptedFormatter(trCtx, macCrypto)
	if err != nil {
		return nil, err
	}

	span.AddEvent("encrypted formatter created",
		trace.WithAttributes(label.String("duration", time.Since(startCreateFormatter).String())))

	restProvider := edv.NewRESTProvider(
		c.EDVServerURL+edvEndpointPathRoot,
		c.VaultID,
		encryptedFormatter,
		edv.WithTLSConfig(c.TLSConfig),
		edv.WithHeaders(func(req *http.Request) (*http.Header, error) {
			return c.signHeader(req, c.EDVCapability)
		}),
	)

	cachedProvider := cachedstore.NewProvider(restProvider, c.CacheProvider)

	return cachedProvider, nil
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

func (c *Config) createEncryptedFormatter(ctx context.Context,
	macCrypto *edv.MACCrypto) (*edv.EncryptedFormatter, error) {
	_, span := tracer.Start(ctx, "edv:createEncryptedFormatter")
	defer span.End()

	startGetKeyHandle := time.Now()

	recipientKH, err := c.KeyManager.Get(c.RecipientKeyID)
	if err != nil {
		return nil, err
	}

	span.AddEvent("recipient key fetched",
		trace.WithAttributes(label.String("duration", time.Since(startGetKeyHandle).String())))

	startRecPubKey := time.Now()

	pubKey, b, err := recipientPublicKey(recipientKH, c.RecipientKeyID)
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

	decrypter := jose.NewJWEDecrypt(nil, c.CryptoService, c.KeyManager)

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
