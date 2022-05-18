/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vdrutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go-ext/component/vdr/orb"
	docdid "github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose/jwk"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/vdr"
	"github.com/square/go-jose/v3"
)

const (
	orbDomain             = "testnet.orb.local"
	didAnchorOrigin       = "https://" + orbDomain
	jsonWebKey2020KeyType = "JsonWebKey2020"
	resolveTimeoutSeconds = 3
)

// CreateVDR creates orb VDR.
func CreateVDR(httpClient *http.Client) (vdrapi.Registry, error) {
	orbVDR, err := orb.New(nil, orb.WithDomain(orbDomain), orb.WithHTTPClient(httpClient))
	if err != nil {
		return nil, err
	}

	return vdr.New(vdr.WithVDR(orbVDR)), nil
}

// CreateDIDDoc creates a new DID document.
func CreateDIDDoc(vdr vdrapi.Registry) (*docdid.Doc, *jwk.JWK, error) {
	doc := &docdid.Doc{}

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate private key: %w", err)
	}

	privateJWK := &jwk.JWK{
		JSONWebKey: jose.JSONWebKey{
			Key:       privateKey,
			KeyID:     uuid.New().String(),
			Algorithm: "ES256",
		},
		Kty: "EC",
		Crv: "P-256",
	}

	publicJWK := &jwk.JWK{
		JSONWebKey: privateJWK.Public(),
		Kty:        "EC",
		Crv:        "P-256",
	}

	vm, err := docdid.NewVerificationMethodFromJWK(doc.ID+"#"+publicJWK.KeyID, jsonWebKey2020KeyType, "", publicJWK)
	if err != nil {
		return nil, nil, fmt.Errorf("create verification method from jwk: %w", err)
	}

	doc.Authentication = append(doc.Authentication, *docdid.NewReferencedVerification(vm, docdid.Authentication))
	doc.AssertionMethod = append(doc.AssertionMethod, *docdid.NewReferencedVerification(vm, docdid.AssertionMethod))

	recoveryKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate recovery key: %w", err)
	}

	updateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate update key: %w", err)
	}

	docResolution, err := vdr.Create(orb.DIDMethod, doc,
		vdrapi.WithOption(orb.RecoveryPublicKeyOpt, recoveryKey.Public()),
		vdrapi.WithOption(orb.UpdatePublicKeyOpt, updateKey.Public()),
		vdrapi.WithOption(orb.AnchorOriginOpt, didAnchorOrigin))
	if err != nil {
		return nil, nil, fmt.Errorf("create did in vdr: %w", err)
	}

	return docResolution.DIDDocument, privateJWK, nil
}

// ResolveDID resolves DID and waits for it to become available for resolution.
func ResolveDID(vdrRegistry vdrapi.Registry, did string, maxRetry int) (*docdid.Doc, error) {
	var docResolution *docdid.DocResolution

	for i := 1; i <= maxRetry; i++ {
		var err error

		docResolution, err = vdrRegistry.Resolve(did)
		if err != nil {
			if !strings.Contains(err.Error(), "DID does not exist") {
				return nil, err
			}

			time.Sleep(resolveTimeoutSeconds * time.Second)

			continue
		}
	}

	return docResolution.DIDDocument, nil
}
