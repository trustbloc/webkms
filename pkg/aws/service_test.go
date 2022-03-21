/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package aws //nolint:testpackage

import (
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/stretchr/testify/require"
)

const (
	localhost = "http://localhost"
)

func TestSign(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		endpoint := localhost
		awsSession, err := session.NewSession(&aws.Config{
			Endpoint:                      &endpoint,
			Region:                        aws.String("ca"),
			CredentialsChainVerboseErrors: aws.Bool(true),
		})
		require.NoError(t, err)

		svc := New(awsSession)

		svc.client = &mockAWSClient{signFunc: func(input *kms.SignInput) (*kms.SignOutput, error) {
			return &kms.SignOutput{
				Signature: []byte("data"),
			}, nil
		}}

		signature, err := svc.Sign([]byte("msg"),
			"aws-kms://arn:aws:kms:ca-central-1:111122223333:alias/800d5768-3fd7-4edd-a4b8-4c81c3e4c147")
		require.NoError(t, err)
		require.Contains(t, string(signature), "data")
	})

	t.Run("failed to sign", func(t *testing.T) {
		endpoint := localhost
		awsSession, err := session.NewSession(&aws.Config{
			Endpoint:                      &endpoint,
			Region:                        aws.String("ca"),
			CredentialsChainVerboseErrors: aws.Bool(true),
		})
		require.NoError(t, err)

		svc := New(awsSession)

		svc.client = &mockAWSClient{signFunc: func(input *kms.SignInput) (*kms.SignOutput, error) {
			return nil, fmt.Errorf("failed to sign")
		}}

		_, err = svc.Sign([]byte("msg"),
			"aws-kms://arn:aws:kms:ca-central-1:111122223333:key/800d5768-3fd7-4edd-a4b8-4c81c3e4c147")
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to sign")
	})

	t.Run("failed to parse key id", func(t *testing.T) {
		endpoint := localhost
		awsSession, err := session.NewSession(&aws.Config{
			Endpoint:                      &endpoint,
			Region:                        aws.String("ca"),
			CredentialsChainVerboseErrors: aws.Bool(true),
		})
		require.NoError(t, err)

		svc := New(awsSession)

		_, err = svc.Sign([]byte("msg"), "key1")
		require.Error(t, err)
		require.Contains(t, err.Error(), "extracting key id from URI failed")
	})
}

func TestGet(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		endpoint := localhost
		awsSession, err := session.NewSession(&aws.Config{
			Endpoint:                      &endpoint,
			Region:                        aws.String("ca"),
			CredentialsChainVerboseErrors: aws.Bool(true),
		})
		require.NoError(t, err)

		svc := New(awsSession)

		keyID, err := svc.Get("key1")
		require.NoError(t, err)
		require.Contains(t, keyID, "key1")
	})
}

func TestPubKeyBytes(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		endpoint := localhost
		awsSession, err := session.NewSession(&aws.Config{
			Endpoint:                      &endpoint,
			Region:                        aws.String("ca"),
			CredentialsChainVerboseErrors: aws.Bool(true),
		})
		require.NoError(t, err)

		svc := New(awsSession)

		svc.client = &mockAWSClient{getPublicKeyFunc: func(input *kms.GetPublicKeyInput) (*kms.GetPublicKeyOutput, error) {
			signingAlgo := "ECDSA_SHA_256"

			return &kms.GetPublicKeyOutput{
				PublicKey:         []byte("publickey"),
				SigningAlgorithms: []*string{&signingAlgo},
			}, nil
		}}

		keyID, keyType, err := svc.ExportPubKeyBytes(
			"aws-kms://arn:aws:kms:ca-central-1:111122223333:key/800d5768-3fd7-4edd-a4b8-4c81c3e4c147")
		require.NoError(t, err)
		require.Contains(t, string(keyID), "publickey")
		require.Contains(t, string(keyType), "ECDSAP256DER")
	})

	t.Run("failed to export public key", func(t *testing.T) {
		endpoint := localhost
		awsSession, err := session.NewSession(&aws.Config{
			Endpoint:                      &endpoint,
			Region:                        aws.String("ca"),
			CredentialsChainVerboseErrors: aws.Bool(true),
		})
		require.NoError(t, err)

		svc := New(awsSession)

		svc.client = &mockAWSClient{getPublicKeyFunc: func(input *kms.GetPublicKeyInput) (*kms.GetPublicKeyOutput, error) {
			return nil, fmt.Errorf("failed to export public key")
		}}

		_, _, err = svc.ExportPubKeyBytes(
			"aws-kms://arn:aws:kms:ca-central-1:111122223333:key/800d5768-3fd7-4edd-a4b8-4c81c3e4c147")
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to export public key")
	})

	t.Run("failed to parse key id", func(t *testing.T) {
		endpoint := localhost
		awsSession, err := session.NewSession(&aws.Config{
			Endpoint:                      &endpoint,
			Region:                        aws.String("ca"),
			CredentialsChainVerboseErrors: aws.Bool(true),
		})
		require.NoError(t, err)

		svc := New(awsSession)

		_, _, err = svc.ExportPubKeyBytes("key1")
		require.Error(t, err)
		require.Contains(t, err.Error(), "extracting key id from URI failed")
	})
}

func TestVerify(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		endpoint := localhost
		awsSession, err := session.NewSession(&aws.Config{
			Endpoint:                      &endpoint,
			Region:                        aws.String("ca"),
			CredentialsChainVerboseErrors: aws.Bool(true),
		})
		require.NoError(t, err)

		svc := New(awsSession)

		svc.client = &mockAWSClient{verifyFunc: func(input *kms.VerifyInput) (*kms.VerifyOutput, error) {
			return &kms.VerifyOutput{}, nil
		}}

		err = svc.Verify([]byte("sign"), []byte("data"),
			"aws-kms://arn:aws:kms:ca-central-1:111122223333:key/800d5768-3fd7-4edd-a4b8-4c81c3e4c147")
		require.NoError(t, err)
	})

	t.Run("failed to verify", func(t *testing.T) {
		endpoint := localhost
		awsSession, err := session.NewSession(&aws.Config{
			Endpoint:                      &endpoint,
			Region:                        aws.String("ca"),
			CredentialsChainVerboseErrors: aws.Bool(true),
		})
		require.NoError(t, err)

		svc := New(awsSession)

		svc.client = &mockAWSClient{verifyFunc: func(input *kms.VerifyInput) (*kms.VerifyOutput, error) {
			return nil, fmt.Errorf("failed to verify")
		}}

		err = svc.Verify([]byte("data"), []byte("msg"),
			"aws-kms://arn:aws:kms:ca-central-1:111122223333:key/800d5768-3fd7-4edd-a4b8-4c81c3e4c147")
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to verify")
	})

	t.Run("failed to parse key id", func(t *testing.T) {
		endpoint := localhost
		awsSession, err := session.NewSession(&aws.Config{
			Endpoint:                      &endpoint,
			Region:                        aws.String("ca"),
			CredentialsChainVerboseErrors: aws.Bool(true),
		})
		require.NoError(t, err)

		svc := New(awsSession)

		err = svc.Verify([]byte("sign"), []byte("msg"), "key1")
		require.Error(t, err)
		require.Contains(t, err.Error(), "extracting key id from URI failed")
	})
}

type mockAWSClient struct {
	signFunc         func(input *kms.SignInput) (*kms.SignOutput, error)
	getPublicKeyFunc func(input *kms.GetPublicKeyInput) (*kms.GetPublicKeyOutput, error)
	verifyFunc       func(input *kms.VerifyInput) (*kms.VerifyOutput, error)
}

func (m *mockAWSClient) Sign(input *kms.SignInput) (*kms.SignOutput, error) {
	if m.signFunc != nil {
		return m.signFunc(input)
	}

	return nil, nil
}

func (m *mockAWSClient) GetPublicKey(input *kms.GetPublicKeyInput) (*kms.GetPublicKeyOutput, error) {
	if m.getPublicKeyFunc != nil {
		return m.getPublicKeyFunc(input)
	}

	return nil, nil
}

func (m *mockAWSClient) Verify(input *kms.VerifyInput) (*kms.VerifyOutput, error) {
	if m.verifyFunc != nil {
		return m.verifyFunc(input)
	}

	return nil, nil
}
