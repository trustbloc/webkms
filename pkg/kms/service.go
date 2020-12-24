/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package kms

import (
	"context"
	"time"

	"github.com/google/tink/go/keyset"
	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite/keyio"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/label"
	"go.opentelemetry.io/otel/trace"

	"github.com/trustbloc/hub-kms/pkg/keystore"
)

// Service provides kms/crypto functionality.
type Service interface {
	CreateKey(ctx context.Context, keystoreID string, kt kms.KeyType) (string, error)
	ExportKey(ctx context.Context, keystoreID, keyID string) ([]byte, error)
	Sign(ctx context.Context, keystoreID, keyID string, msg []byte) ([]byte, error)
	Verify(ctx context.Context, keystoreID, keyID string, sig, msg []byte) error
	Encrypt(ctx context.Context, keystoreID, keyID string, msg, aad []byte) ([]byte, []byte, error)
	Decrypt(ctx context.Context, keystoreID, keyID string, cipher, aad, nonce []byte) ([]byte, error)
	ComputeMAC(ctx context.Context, keystoreID, keyID string, data []byte) ([]byte, error)
	VerifyMAC(ctx context.Context, keystoreID, keyID string, mac, data []byte) error
	WrapKey(ctx context.Context, keystoreID, keyID string, cek, apu, apv []byte,
		recipientPubKey *crypto.PublicKey) (*crypto.RecipientWrappedKey, error)
	UnwrapKey(ctx context.Context, keystoreID, keyID string, recipientWK *crypto.RecipientWrappedKey,
		senderPubKey *crypto.PublicKey) ([]byte, error)

	// CryptoBox operations.
	Easy(ctx context.Context, keystoreID, keyID string, payload, nonce, theirPub []byte) ([]byte, error)
	EasyOpen(ctx context.Context, keystoreID string, cipherText, nonce, theirPub, myPub []byte) ([]byte, error)
	SealOpen(ctx context.Context, keystoreID string, cipher, myPub []byte) ([]byte, error)
}

// CryptoBox provides an elliptic-curve-based authenticated encryption scheme (used in legacy packer).
type CryptoBox interface {
	Easy(payload, nonce, theirPub []byte, myKID string) ([]byte, error)
	EasyOpen(cipherText, nonce, theirPub, myPub []byte) ([]byte, error)
	SealOpen(cipherText, myPub []byte) ([]byte, error)
}

// Provider contains dependencies for the KMS service.
type Provider interface {
	KeystoreService() keystore.Service
	KeyManager() kms.KeyManager
	Crypto() crypto.Crypto
	CryptoBox() CryptoBox
}

type service struct {
	keystore   keystore.Service
	keyManager kms.KeyManager
	crypto     crypto.Crypto
	cryptoBox  CryptoBox
}

var tracer = otel.Tracer("hub-kms/kms") //nolint:gochecknoglobals // ignore

// NewService returns a new Service instance.
func NewService(provider Provider) Service {
	return &service{
		keystore:   provider.KeystoreService(),
		keyManager: provider.KeyManager(),
		crypto:     provider.Crypto(),
		cryptoBox:  provider.CryptoBox(),
	}
}

// CreateKey creates a new key and associates it with Keystore.
func (s *service) CreateKey(ctx context.Context, keystoreID string,
	kt kms.KeyType) (string, error) { //nolint:funlen // TODO refactor
	trCtx, span := tracer.Start(ctx, "kms:CreateKey")
	defer span.End()

	span.SetAttributes(label.String("keystoreID", keystoreID))

	start := time.Now()

	keyID, _, err := s.keyManager.Create(kt)
	if err != nil {
		return "", NewServiceError(createKeyFailed, err)
	}

	span.AddEvent("Create completed",
		trace.WithAttributes(label.String("duration", time.Since(start).String())))

	span.SetAttributes(label.String("keyID", keyID))

	startGet := time.Now()

	k, err := s.keystore.Get(trCtx, keystoreID)
	if err != nil {
		return "", NewServiceError(getKeystoreFailed, err)
	}

	span.AddEvent("keystore.Get completed",
		trace.WithAttributes(label.String("duration", time.Since(startGet).String())))

	k.KeyIDs = append(k.KeyIDs, keyID)

	startPut := time.Now()

	err = s.keystore.Save(trCtx, k)
	if err != nil {
		return "", NewServiceError(saveKeystoreFailed, err)
	}

	span.AddEvent("keystore.Save completed",
		trace.WithAttributes(label.String("duration", time.Since(startPut).String())))

	return keyID, nil
}

// ExportKey exports a public key.
func (s *service) ExportKey(ctx context.Context, keystoreID, keyID string) ([]byte, error) {
	trCtx, span := tracer.Start(ctx, "kms:ExportKey")
	defer span.End()

	span.SetAttributes(label.String("keystoreID", keystoreID))
	span.SetAttributes(label.String("keyID", keyID))

	if err := s.checkKey(trCtx, span, keystoreID, keyID); err != nil {
		return nil, err
	}

	start := time.Now()

	b, err := s.keyManager.ExportPubKeyBytes(keyID)
	if err != nil {
		return nil, NewServiceError(exportKeyFailed, err)
	}

	span.AddEvent("ExportPubKeyBytes completed",
		trace.WithAttributes(label.String("duration", time.Since(start).String())))

	return b, nil
}

// Sign signs a message.
//nolint:dupl // TODO refactor
func (s *service) Sign(ctx context.Context, keystoreID, keyID string, msg []byte) ([]byte, error) {
	trCtx, span := tracer.Start(ctx, "kms:Sign")
	defer span.End()

	span.SetAttributes(label.String("keystoreID", keystoreID))
	span.SetAttributes(label.String("keyID", keyID))

	kh, err := s.getKeyHandle(trCtx, span, keystoreID, keyID)
	if err != nil {
		return nil, err
	}

	start := time.Now()

	sig, err := s.crypto.Sign(msg, kh)
	if err != nil {
		return nil, NewServiceError(signMessageFailed, err)
	}

	span.AddEvent("Sign completed",
		trace.WithAttributes(label.String("duration", time.Since(start).String())))

	return sig, nil
}

// Verify verifies a signature for the message.
func (s *service) Verify(ctx context.Context, keystoreID, keyID string, sig, msg []byte) error {
	trCtx, span := tracer.Start(ctx, "kms:Verify")
	defer span.End()

	span.SetAttributes(label.String("keystoreID", keystoreID))
	span.SetAttributes(label.String("keyID", keyID))

	kh, err := s.getKeyHandle(trCtx, span, keystoreID, keyID)
	if err != nil {
		return err
	}

	pub, err := kh.(*keyset.Handle).Public()
	if err != nil {
		return NewServiceError(noPublicKeyFailure, err)
	}

	start := time.Now()

	err = s.crypto.Verify(sig, msg, pub)
	if err != nil {
		return NewServiceError(verifySignatureFailed, err)
	}

	span.AddEvent("Verify completed",
		trace.WithAttributes(label.String("duration", time.Since(start).String())))

	return nil
}

// Encrypt encrypts a message with additional authenticated data (AAD).
func (s *service) Encrypt(ctx context.Context, keystoreID, keyID string, msg, aad []byte) ([]byte, []byte, error) {
	trCtx, span := tracer.Start(ctx, "kms:Encrypt")
	defer span.End()

	span.SetAttributes(label.String("keystoreID", keystoreID))
	span.SetAttributes(label.String("keyID", keyID))

	kh, err := s.getKeyHandle(trCtx, span, keystoreID, keyID)
	if err != nil {
		return nil, nil, err
	}

	start := time.Now()

	cipher, nonce, err := s.crypto.Encrypt(msg, aad, kh)
	if err != nil {
		return nil, nil, NewServiceError(encryptMessageFailed, err)
	}

	span.AddEvent("Encrypt completed",
		trace.WithAttributes(label.String("duration", time.Since(start).String())))

	return cipher, nonce, nil
}

// Decrypt decrypts a cipher with AAD and a nonce.
func (s *service) Decrypt(ctx context.Context, keystoreID, keyID string, cipher, aad, nonce []byte) ([]byte, error) {
	trCtx, span := tracer.Start(ctx, "kms:Decrypt")
	defer span.End()

	span.SetAttributes(label.String("keystoreID", keystoreID))
	span.SetAttributes(label.String("keyID", keyID))

	kh, err := s.getKeyHandle(trCtx, span, keystoreID, keyID)
	if err != nil {
		return nil, err
	}

	start := time.Now()

	plain, err := s.crypto.Decrypt(cipher, aad, nonce, kh)
	if err != nil {
		return nil, NewServiceError(decryptCipherFailed, err)
	}

	span.AddEvent("Decrypt completed",
		trace.WithAttributes(label.String("duration", time.Since(start).String())))

	return plain, nil
}

// ComputeMAC computes message authentication code (MAC) for data.
//nolint:dupl // TODO refactor
func (s *service) ComputeMAC(ctx context.Context, keystoreID, keyID string, data []byte) ([]byte, error) {
	trCtx, span := tracer.Start(ctx, "kms:ComputeMAC")
	defer span.End()

	span.SetAttributes(label.String("keystoreID", keystoreID))
	span.SetAttributes(label.String("keyID", keyID))

	kh, err := s.getKeyHandle(trCtx, span, keystoreID, keyID)
	if err != nil {
		return nil, err
	}

	start := time.Now()

	mac, err := s.crypto.ComputeMAC(data, kh)
	if err != nil {
		return nil, NewServiceError(computeMACFailed, err)
	}

	span.AddEvent("ComputeMAC completed",
		trace.WithAttributes(label.String("duration", time.Since(start).String())))

	return mac, nil
}

// VerifyMAC determines if the given mac is a correct message authentication code (MAC) for data.
func (s *service) VerifyMAC(ctx context.Context, keystoreID, keyID string, mac, data []byte) error {
	trCtx, span := tracer.Start(ctx, "kms:VerifyMAC")
	defer span.End()

	span.SetAttributes(label.String("keystoreID", keystoreID))
	span.SetAttributes(label.String("keyID", keyID))

	kh, err := s.getKeyHandle(trCtx, span, keystoreID, keyID)
	if err != nil {
		return err
	}

	start := time.Now()

	err = s.crypto.VerifyMAC(mac, data, kh)
	if err != nil {
		return NewServiceError(verifyMACFailed, err)
	}

	span.AddEvent("VerifyMAC completed",
		trace.WithAttributes(label.String("duration", time.Since(start).String())))

	return nil
}

// WrapKey wraps cek for the recipient with public key 'recipientPubKey'.
func (s *service) WrapKey(ctx context.Context, keystoreID, keyID string, cek, apu, apv []byte,
	recipientPubKey *crypto.PublicKey) (*crypto.RecipientWrappedKey, error) {
	trCtx, span := tracer.Start(ctx, "kms:WrapKey")
	defer span.End()

	span.SetAttributes(label.String("keystoreID", keystoreID))
	span.SetAttributes(label.String("keyID", keyID))

	if keyID != "" {
		kh, err := s.getKeyHandle(trCtx, span, keystoreID, keyID)
		if err != nil {
			return nil, err
		}

		// ECDH-1PU key wrapping (Authcrypt)
		start := time.Now()

		recipientWrappedKey, err := s.crypto.WrapKey(cek, apu, apv, recipientPubKey, crypto.WithSender(kh))
		if err != nil {
			return nil, NewServiceError(wrapKeyFailed, err)
		}

		span.AddEvent("WrapKey (Authcrypt) completed",
			trace.WithAttributes(label.String("duration", time.Since(start).String())))

		return recipientWrappedKey, nil
	}

	start := time.Now()

	recipientWrappedKey, err := s.crypto.WrapKey(cek, apu, apv, recipientPubKey)
	if err != nil {
		return nil, NewServiceError(wrapKeyFailed, err)
	}

	span.AddEvent("WrapKey (Anoncrypt) completed",
		trace.WithAttributes(label.String("duration", time.Since(start).String())))

	return recipientWrappedKey, nil
}

// UnwrapKey unwraps a key in recipientWK.
func (s *service) UnwrapKey(ctx context.Context, keystoreID, keyID string, recipientWK *crypto.RecipientWrappedKey,
	senderPubKey *crypto.PublicKey) ([]byte, error) {
	trCtx, span := tracer.Start(ctx, "kms:UnwrapKey")
	defer span.End()

	span.SetAttributes(label.String("keystoreID", keystoreID))
	span.SetAttributes(label.String("keyID", keyID))

	kh, err := s.getKeyHandle(trCtx, span, keystoreID, keyID)
	if err != nil {
		return nil, err
	}

	if senderPubKey != nil {
		senderKH, e := keyio.PublicKeyToKeysetHandle(senderPubKey)
		if e != nil {
			return nil, NewServiceError(unwrapKeyFailed, e)
		}

		// ECDH-1PU key unwrapping (Authcrypt)
		start := time.Now()

		cek, e := s.crypto.UnwrapKey(recipientWK, kh, crypto.WithSender(senderKH))
		if e != nil {
			return nil, NewServiceError(unwrapKeyFailed, e)
		}

		span.AddEvent("UnwrapKey (Authcrypt) completed",
			trace.WithAttributes(label.String("duration", time.Since(start).String())))

		return cek, nil
	}

	start := time.Now()

	cek, err := s.crypto.UnwrapKey(recipientWK, kh)
	if err != nil {
		return nil, NewServiceError(unwrapKeyFailed, err)
	}

	span.AddEvent("UnwrapKey (Anoncrypt) completed",
		trace.WithAttributes(label.String("duration", time.Since(start).String())))

	return cek, nil
}

func (s *service) getKeyHandle(ctx context.Context, span trace.Span, keystoreID, keyID string) (interface{}, error) {
	if err := s.checkKey(ctx, span, keystoreID, keyID); err != nil {
		return nil, err
	}

	kh, err := s.keyManager.Get(keyID)
	if err != nil {
		return nil, NewServiceError(getKeyFailed, err)
	}

	return kh, nil
}

func (s *service) checkKey(ctx context.Context, span trace.Span, keystoreID, keyID string) error {
	start := time.Now()

	k, err := s.keystore.Get(ctx, keystoreID)
	if err != nil {
		return NewServiceError(getKeystoreFailed, err)
	}

	span.AddEvent("keystore.Get completed",
		trace.WithAttributes(label.String("duration", time.Since(start).String())))

	if len(k.KeyIDs) == 0 {
		return NewServiceError(noKeysFailure, nil)
	}

	found := false

	for _, id := range k.KeyIDs {
		if id == keyID {
			found = true

			break
		}
	}

	if !found {
		return NewServiceError(invalidKeyFailure, nil)
	}

	return nil
}
