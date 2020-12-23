/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package kms

import (
	"context"
	"time"

	"go.opentelemetry.io/otel/label"
	"go.opentelemetry.io/otel/trace"
)

// Easy seals a message with a provided nonce.
func (s *service) Easy(ctx context.Context, keystoreID, keyID string, payload, nonce, theirPub []byte) ([]byte, error) {
	trCtx, span := tracer.Start(ctx, "kms:Easy")
	defer span.End()

	span.SetAttributes(label.String("keystoreID", keystoreID))
	span.SetAttributes(label.String("keyID", keyID))

	if err := s.checkKey(trCtx, span, keystoreID, keyID); err != nil {
		return nil, err
	}

	start := time.Now()

	cipher, err := s.cryptoBox.Easy(payload, nonce, theirPub, keyID)
	if err != nil {
		return nil, NewServiceError(easyMessageFailed, err)
	}

	span.AddEvent("Easy completed",
		trace.WithAttributes(label.String("duration", time.Since(start).String())))

	return cipher, nil
}

// EasyOpen unseals a message sealed with Easy, where the nonce is provided.
func (s *service) EasyOpen(ctx context.Context, keystoreID string,
	cipherText, nonce, theirPub, myPub []byte) ([]byte, error) {
	trCtx, span := tracer.Start(ctx, "kms:EasyOpen")
	defer span.End()

	span.SetAttributes(label.String("keystoreID", keystoreID))

	startGet := time.Now()

	if _, err := s.keystore.Get(trCtx, keystoreID); err != nil {
		return nil, NewServiceError(getKeystoreFailed, err)
	}

	span.AddEvent("keystore.Get completed",
		trace.WithAttributes(label.String("duration", time.Since(startGet).String())))

	start := time.Now()

	plain, err := s.cryptoBox.EasyOpen(cipherText, nonce, theirPub, myPub)
	if err != nil {
		return nil, NewServiceError(easyOpenMessageFailed, err)
	}

	span.AddEvent("EasyOpen completed",
		trace.WithAttributes(label.String("duration", time.Since(start).String())))

	return plain, nil
}

// SealOpen decrypts a payload encrypted with Seal.
func (s *service) SealOpen(ctx context.Context, keystoreID string, cipher, myPub []byte) ([]byte, error) {
	trCtx, span := tracer.Start(ctx, "kms:SealOpen")
	defer span.End()

	span.SetAttributes(label.String("keystoreID", keystoreID))

	startGet := time.Now()

	if _, err := s.keystore.Get(trCtx, keystoreID); err != nil {
		return nil, NewServiceError(getKeystoreFailed, err)
	}

	span.AddEvent("keystore.Get completed",
		trace.WithAttributes(label.String("duration", time.Since(startGet).String())))

	start := time.Now()

	plain, err := s.cryptoBox.SealOpen(cipher, myPub)
	if err != nil {
		return nil, NewServiceError(sealOpenPayloadFailed, err)
	}

	span.AddEvent("SealOpen completed",
		trace.WithAttributes(label.String("duration", time.Since(start).String())))

	return plain, nil
}
