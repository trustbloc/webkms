/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package zcapld

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	cryptoapi "github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/jsonld"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/ed25519signature2018"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util/signature"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/fingerprint"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/igor-pavlenko/httpsignatures-go"
	"github.com/piprate/json-gold/ld"
	"github.com/trustbloc/edge-core/pkg/zcapld"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/label"
	"go.opentelemetry.io/otel/trace"
)

const (
	zcapsStoreName = "zcaps"
)

// Service to provide zcapld functionality.
type Service struct {
	keyManager   kms.KeyManager
	crypto       cryptoapi.Crypto
	store        storage.Store
	jsonLDLoader ld.DocumentLoader
}

var tracer = otel.Tracer("kms/zcapld") //nolint:gochecknoglobals // ignore

// New return zcap service.
func New(keyManager kms.KeyManager, crypto cryptoapi.Crypto, sp storage.Provider,
	jsonLDLoader ld.DocumentLoader) (*Service, error) {
	store, err := sp.OpenStore(zcapsStoreName)
	if err != nil {
		return nil, fmt.Errorf("failed to open store: %w", err)
	}

	return &Service{
		keyManager:   keyManager,
		crypto:       crypto,
		store:        store,
		jsonLDLoader: jsonLDLoader,
	}, nil
}

// CreateDIDKey create did key.
func (s *Service) CreateDIDKey(ctx context.Context) (string, error) {
	_, span := tracer.Start(ctx, "zcapld:CreateDIDKey")
	defer span.End()

	start := time.Now()

	signer, err := signature.NewCryptoSigner(s.crypto, s.keyManager, kms.ED25519)
	if err != nil {
		return "", fmt.Errorf("failed to create crypto signer: %w", err)
	}

	span.AddEvent("signature.NewCryptoSigner completed",
		trace.WithAttributes(label.String("duration", time.Since(start).String())))

	return didKeyURL(signer.PublicKeyBytes()), nil
}

// SignHeader sign header.
func (s *Service) SignHeader(req *http.Request, capabilityBytes []byte) (*http.Header, error) {
	capability, err := zcapld.ParseCapability(capabilityBytes)
	if err != nil {
		return nil, err
	}

	compressedZcap, err := CompressZCAP(capability)
	if err != nil {
		return nil, err
	}

	action := "write"
	if req.Method == http.MethodGet {
		action = "read"
	}

	req.Header.Set(zcapld.CapabilityInvocationHTTPHeader,
		fmt.Sprintf(`zcap capability="%s",action="%s"`, compressedZcap, action))

	hs := httpsignatures.NewHTTPSignatures(&zcapld.AriesDIDKeySecrets{})
	hs.SetSignatureHashAlgorithm(&zcapld.AriesDIDKeySignatureHashAlgorithm{
		Crypto: s.crypto,
		KMS:    s.keyManager,
	})

	err = hs.Sign(capability.Invoker, req)
	if err != nil {
		return nil, err
	}

	return &req.Header, nil
}

// NewCapability creates a new capability and puts it in storage.
func (s *Service) NewCapability(ctx context.Context, options ...zcapld.CapabilityOption) (*zcapld.Capability, error) {
	_, span := tracer.Start(ctx, "zcapld:NewCapability")
	defer span.End()

	start := time.Now()

	signer, err := signature.NewCryptoSigner(s.crypto, s.keyManager, kms.ED25519)
	if err != nil {
		return nil, fmt.Errorf("failed to create a new signer: %w", err)
	}

	span.AddEvent("signature.NewCryptoSigner completed",
		trace.WithAttributes(label.String("duration", time.Since(start).String())))

	startNewCapability := time.Now()

	zcap, err := zcapld.NewCapability(
		&zcapld.Signer{
			SignatureSuite:     ed25519signature2018.New(suite.WithSigner(signer)),
			SuiteType:          ed25519signature2018.SignatureType,
			VerificationMethod: didKeyURL(signer.PublicKeyBytes()),
			ProcessorOpts:      []jsonld.ProcessorOpts{jsonld.WithDocumentLoader(s.jsonLDLoader)},
		},
		options...,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create zcap: %w", err)
	}

	span.AddEvent("zcapld.NewCapability completed",
		trace.WithAttributes(label.String("duration", time.Since(startNewCapability).String())))

	raw, err := json.Marshal(zcap)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal zcap: %w", err)
	}

	startPut := time.Now()

	err = s.store.Put(zcap.ID, raw)
	if err != nil {
		return nil, fmt.Errorf("failed to store zcap: %w", err)
	}

	span.AddEvent("store.Put completed",
		trace.WithAttributes(label.String("duration", time.Since(startPut).String())))

	return zcap, nil
}

// Resolve the capability.
func (s *Service) Resolve(uri string) (*zcapld.Capability, error) {
	raw, err := s.store.Get(uri)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch zcap from storage: %w", err)
	}

	return zcapld.ParseCapability(raw)
}

// KMS returns the kms.KeyManager.
func (s *Service) KMS() kms.KeyManager {
	return s.keyManager
}

// Crypto returns the cryptoapi.Crypto.
func (s *Service) Crypto() cryptoapi.Crypto {
	return s.crypto
}

// CompressZCAP gzips the zcap, then base64URL-encodes it.
func CompressZCAP(zcap *zcapld.Capability) (string, error) {
	raw, err := json.Marshal(zcap)
	if err != nil {
		return "", err
	}

	compressed := bytes.NewBuffer(nil)

	w := gzip.NewWriter(compressed)

	_, err = w.Write(raw)
	if err != nil {
		return "", err
	}

	err = w.Close()
	if err != nil {
		return "", err
	}

	return base64.URLEncoding.EncodeToString(compressed.Bytes()), nil
}

func didKeyURL(pubKeyBytes []byte) string {
	_, didKeyURL := fingerprint.CreateDIDKey(pubKeyBytes)

	return didKeyURL
}
