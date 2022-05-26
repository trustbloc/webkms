/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package aws //nolint:testpackage

import (
	"fmt"
	"testing"
	"time"

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

		svc := New(awsSession, &mockMetrics{}, "")

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

		svc := New(awsSession, &mockMetrics{}, "")

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

		svc := New(awsSession, &mockMetrics{}, "")

		_, err = svc.Sign([]byte("msg"), "key1")
		require.Error(t, err)
		require.Contains(t, err.Error(), "extracting key id from URI failed")
	})
}

func TestHealthCheck(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		endpoint := localhost
		awsSession, err := session.NewSession(&aws.Config{
			Endpoint:                      &endpoint,
			Region:                        aws.String("ca"),
			CredentialsChainVerboseErrors: aws.Bool(true),
		})
		require.NoError(t, err)

		svc := New(awsSession, &mockMetrics{},
			"aws-kms://arn:aws:kms:ca-central-1:111122223333:key/800d5768-3fd7-4edd-a4b8-4c81c3e4c147")

		svc.client = &mockAWSClient{describeKeyFunc: func(input *kms.DescribeKeyInput) (*kms.DescribeKeyOutput, error) {
			return &kms.DescribeKeyOutput{}, nil
		}}

		err = svc.HealthCheck()
		require.NoError(t, err)
	})

	t.Run("failed to list keys", func(t *testing.T) {
		endpoint := localhost
		awsSession, err := session.NewSession(&aws.Config{
			Endpoint:                      &endpoint,
			Region:                        aws.String("ca"),
			CredentialsChainVerboseErrors: aws.Bool(true),
		})
		require.NoError(t, err)

		svc := New(awsSession, &mockMetrics{},
			"aws-kms://arn:aws:kms:ca-central-1:111122223333:key/800d5768-3fd7-4edd-a4b8-4c81c3e4c147")

		svc.client = &mockAWSClient{describeKeyFunc: func(input *kms.DescribeKeyInput) (*kms.DescribeKeyOutput, error) {
			return nil, fmt.Errorf("failed to list keys")
		}}

		err = svc.HealthCheck()
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to list keys")
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

		svc := New(awsSession, &mockMetrics{}, "")

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

		svc := New(awsSession, &mockMetrics{}, "")

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

		svc := New(awsSession, &mockMetrics{}, "")

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

		svc := New(awsSession, &mockMetrics{}, "")

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

		svc := New(awsSession, &mockMetrics{}, "")

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

		svc := New(awsSession, &mockMetrics{}, "")

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

		svc := New(awsSession, &mockMetrics{}, "")

		err = svc.Verify([]byte("sign"), []byte("msg"), "key1")
		require.Error(t, err)
		require.Contains(t, err.Error(), "extracting key id from URI failed")
	})
}

type mockAWSClient struct {
	signFunc         func(input *kms.SignInput) (*kms.SignOutput, error)
	getPublicKeyFunc func(input *kms.GetPublicKeyInput) (*kms.GetPublicKeyOutput, error)
	verifyFunc       func(input *kms.VerifyInput) (*kms.VerifyOutput, error)
	describeKeyFunc  func(input *kms.DescribeKeyInput) (*kms.DescribeKeyOutput, error)
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

func (m *mockAWSClient) DescribeKey(input *kms.DescribeKeyInput) (*kms.DescribeKeyOutput, error) {
	if m.describeKeyFunc != nil {
		return m.describeKeyFunc(input)
	}

	return nil, nil
}

type mockMetrics struct{}

func (m *mockMetrics) SignCount() {
}

func (m *mockMetrics) SignTime(value time.Duration) {
}

func (m *mockMetrics) ExportPublicKeyCount() {
}

func (m *mockMetrics) ExportPublicKeyTime(value time.Duration) {
}

func (m *mockMetrics) VerifyCount() {
}

func (m *mockMetrics) VerifyTime(value time.Duration) {
}
