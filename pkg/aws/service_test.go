/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package aws //nolint:testpackage

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	arieskms "github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/stretchr/testify/require"
)

func TestSign(t *testing.T) {
	awsConfig := &aws.Config{
		Region: "ca",
	}

	t.Run("success", func(t *testing.T) {
		svc := New(awsConfig, &mockMetrics{}, "", []Opts{}...)

		svc.client = &mockAWSClient{signFunc: func(ctx context.Context, params *kms.SignInput,
			optFns ...func(*kms.Options)) (*kms.SignOutput, error) {
			return &kms.SignOutput{
				Signature: []byte("data"),
			}, nil
		}, describeKeyFunc: func(ctx context.Context, params *kms.DescribeKeyInput,
			optFns ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
			return &kms.DescribeKeyOutput{
				KeyMetadata: &types.KeyMetadata{
					SigningAlgorithms: []types.SigningAlgorithmSpec{types.SigningAlgorithmSpecEcdsaSha256},
					KeySpec:           types.KeySpecEccNistP256,
				},
			}, nil
		}}

		signature, err := svc.Sign([]byte("msg"),
			"aws-kms://arn:aws:kms:ca-central-1:111122223333:alias/800d5768-3fd7-4edd-a4b8-4c81c3e4c147")
		require.NoError(t, err)
		require.Contains(t, string(signature), "data")
	})

	t.Run("failed to sign", func(t *testing.T) {
		svc := New(awsConfig, &mockMetrics{}, "", []Opts{}...)

		svc.client = &mockAWSClient{signFunc: func(ctx context.Context, params *kms.SignInput,
			optFns ...func(*kms.Options)) (*kms.SignOutput, error) {
			return nil, fmt.Errorf("failed to sign")
		}, describeKeyFunc: func(ctx context.Context, params *kms.DescribeKeyInput,
			optFns ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
			return &kms.DescribeKeyOutput{
				KeyMetadata: &types.KeyMetadata{
					SigningAlgorithms: []types.SigningAlgorithmSpec{types.SigningAlgorithmSpecEcdsaSha256},
				},
			}, nil
		}}

		_, err := svc.Sign([]byte("msg"),
			"aws-kms://arn:aws:kms:ca-central-1:111122223333:key/800d5768-3fd7-4edd-a4b8-4c81c3e4c147")
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to sign")
	})

	t.Run("failed to parse key id", func(t *testing.T) {
		svc := New(awsConfig, &mockMetrics{}, "", []Opts{}...)

		_, err := svc.Sign([]byte("msg"), "aws-kms://arn:aws:kms:key1")
		require.Error(t, err)
		require.Contains(t, err.Error(), "extracting key id from URI failed")
	})
}

func TestHealthCheck(t *testing.T) {
	awsConfig := &aws.Config{
		Region: "ca",
	}

	t.Run("success", func(t *testing.T) {
		svc := New(awsConfig, &mockMetrics{},
			"aws-kms://arn:aws:kms:ca-central-1:111122223333:key/800d5768-3fd7-4edd-a4b8-4c81c3e4c147",
			[]Opts{}...)

		svc.client = &mockAWSClient{describeKeyFunc: func(ctx context.Context, params *kms.DescribeKeyInput,
			optFns ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
			return &kms.DescribeKeyOutput{}, nil
		}}

		err := svc.HealthCheck()
		require.NoError(t, err)
	})

	t.Run("failed to list keys", func(t *testing.T) {
		svc := New(awsConfig, &mockMetrics{},
			"aws-kms://arn:aws:kms:ca-central-1:111122223333:key/800d5768-3fd7-4edd-a4b8-4c81c3e4c147",
			[]Opts{}...)

		svc.client = &mockAWSClient{describeKeyFunc: func(ctx context.Context, params *kms.DescribeKeyInput,
			optFns ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
			return nil, fmt.Errorf("failed to list keys")
		}}

		err := svc.HealthCheck()
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to list keys")
	})
}

func TestCreate(t *testing.T) {
	awsConfig := &aws.Config{
		Region: "ca",
	}

	t.Run("success", func(t *testing.T) {
		svc := New(awsConfig, &mockMetrics{}, "", []Opts{}...)

		keyID := "key1"

		svc.client = &mockAWSClient{createKeyFunc: func(ctx context.Context, params *kms.CreateKeyInput,
			optFns ...func(*kms.Options)) (*kms.CreateKeyOutput, error) {
			return &kms.CreateKeyOutput{KeyMetadata: &types.KeyMetadata{KeyId: &keyID}}, nil
		}}

		result, _, err := svc.Create(arieskms.ECDSAP256DER)
		require.NoError(t, err)
		require.Contains(t, result, keyID)
	})

	t.Run("success: with key alias prefix", func(t *testing.T) {
		svc := New(awsConfig, &mockMetrics{}, "", WithKeyAliasPrefix("dummyKeyAlias"))

		keyID := "key1"

		svc.client = &mockAWSClient{
			createKeyFunc: func(ctx context.Context, params *kms.CreateKeyInput,
				optFns ...func(*kms.Options)) (*kms.CreateKeyOutput, error) {
				return &kms.CreateKeyOutput{KeyMetadata: &types.KeyMetadata{KeyId: &keyID}}, nil
			},
			createAliasFunc: func(ctx context.Context, params *kms.CreateAliasInput,
				optFns ...func(*kms.Options)) (*kms.CreateAliasOutput, error) {
				return &kms.CreateAliasOutput{}, nil
			},
		}

		result, _, err := svc.Create(arieskms.ECDSAP256DER)
		require.NoError(t, err)
		require.Contains(t, result, keyID)
	})

	t.Run("key not supported", func(t *testing.T) {
		svc := New(awsConfig, &mockMetrics{}, "", []Opts{}...)

		_, _, err := svc.Create(arieskms.ED25519)
		require.Error(t, err)
		require.Contains(t, err.Error(), "key not supported ED25519")
	})
}

func TestGet(t *testing.T) {
	awsConfig := aws.Config{
		Region: "ca",
	}

	t.Run("success", func(t *testing.T) {
		svc := New(&awsConfig, &mockMetrics{}, "", []Opts{}...)

		keyID, err := svc.Get("key1")
		require.NoError(t, err)
		require.Contains(t, keyID, "key1")
	})
}

func TestCreateAndPubKeyBytes(t *testing.T) {
	awsConfig := aws.Config{
		Region: "ca",
	}

	t.Run("success", func(t *testing.T) {
		keyID := "aws-kms://arn:aws:kms:ca-central-1:111122223333:key/800d5768-3fd7-4edd-a4b8-4c81c3e4c147"

		svc := New(&awsConfig, &mockMetrics{}, "", []Opts{}...)

		svc.client = &mockAWSClient{
			getPublicKeyFunc: func(ctx context.Context, params *kms.GetPublicKeyInput,
				optFns ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
				return &kms.GetPublicKeyOutput{
					PublicKey:         []byte("publickey"),
					SigningAlgorithms: []types.SigningAlgorithmSpec{types.SigningAlgorithmSpecEcdsaSha256},
				}, nil
			},
			createKeyFunc: func(ctx context.Context, params *kms.CreateKeyInput,
				optFns ...func(*kms.Options)) (*kms.CreateKeyOutput, error) {
				return &kms.CreateKeyOutput{KeyMetadata: &types.KeyMetadata{KeyId: &keyID}}, nil
			},
		}

		keyID, publicKey, err := svc.CreateAndExportPubKeyBytes(arieskms.ECDSAP256DER)
		require.NoError(t, err)
		require.Contains(t, string(publicKey), "publickey")
		require.Contains(t, keyID, keyID)
	})
}

func TestSignMulti(t *testing.T) {
	awsConfig := aws.Config{
		Region: "ca",
	}

	svc := New(&awsConfig, &mockMetrics{}, "", []Opts{}...)

	_, err := svc.SignMulti(nil, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
}

func TestPubKeyBytes(t *testing.T) {
	awsConfig := &aws.Config{
		Region: "ca",
	}

	t.Run("success", func(t *testing.T) {
		svc := New(awsConfig, &mockMetrics{}, "", []Opts{}...)

		svc.client = &mockAWSClient{getPublicKeyFunc: func(ctx context.Context, params *kms.GetPublicKeyInput,
			optFns ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
			return &kms.GetPublicKeyOutput{
				PublicKey:         []byte("publickey"),
				SigningAlgorithms: []types.SigningAlgorithmSpec{types.SigningAlgorithmSpecEcdsaSha256},
			}, nil
		}}

		keyID, keyType, err := svc.ExportPubKeyBytes(
			"aws-kms://arn:aws:kms:ca-central-1:111122223333:key/800d5768-3fd7-4edd-a4b8-4c81c3e4c147")
		require.NoError(t, err)
		require.Contains(t, string(keyID), "publickey")
		require.Contains(t, string(keyType), "ECDSAP256DER")
	})

	t.Run("failed to export public key", func(t *testing.T) {
		svc := New(awsConfig, &mockMetrics{}, "", []Opts{}...)

		svc.client = &mockAWSClient{getPublicKeyFunc: func(ctx context.Context, params *kms.GetPublicKeyInput,
			optFns ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
			return nil, fmt.Errorf("failed to export public key")
		}}

		_, _, err := svc.ExportPubKeyBytes(
			"aws-kms://arn:aws:kms:ca-central-1:111122223333:key/800d5768-3fd7-4edd-a4b8-4c81c3e4c147")
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to export public key")
	})

	t.Run("failed to parse key id", func(t *testing.T) {
		svc := New(awsConfig, &mockMetrics{}, "", []Opts{}...)

		_, _, err := svc.ExportPubKeyBytes("aws-kms://arn:aws:kms:key1")
		require.Error(t, err)
		require.Contains(t, err.Error(), "extracting key id from URI failed")
	})
}

type mockAWSClient struct {
	signFunc func(ctx context.Context, params *kms.SignInput,
		optFns ...func(*kms.Options)) (*kms.SignOutput, error)
	getPublicKeyFunc func(ctx context.Context, params *kms.GetPublicKeyInput,
		optFns ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error)
	verifyFunc func(ctx context.Context, params *kms.VerifyInput,
		optFns ...func(*kms.Options)) (*kms.VerifyOutput, error)
	describeKeyFunc func(ctx context.Context, params *kms.DescribeKeyInput,
		optFns ...func(*kms.Options)) (*kms.DescribeKeyOutput, error)
	createKeyFunc func(ctx context.Context, params *kms.CreateKeyInput,
		optFns ...func(*kms.Options)) (*kms.CreateKeyOutput, error)
	createAliasFunc func(ctx context.Context, params *kms.CreateAliasInput,
		optFns ...func(*kms.Options)) (*kms.CreateAliasOutput, error)
}

func (m *mockAWSClient) Sign(ctx context.Context, params *kms.SignInput,
	optFns ...func(*kms.Options)) (*kms.SignOutput, error) {
	if m.signFunc != nil {
		return m.signFunc(ctx, params, optFns...)
	}

	return nil, nil //nolint:nilnil
}

func (m *mockAWSClient) GetPublicKey(ctx context.Context, params *kms.GetPublicKeyInput,
	optFns ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
	if m.getPublicKeyFunc != nil {
		return m.getPublicKeyFunc(ctx, params, optFns...)
	}

	return nil, nil //nolint:nilnil
}

func (m *mockAWSClient) Verify(ctx context.Context, params *kms.VerifyInput,
	optFns ...func(*kms.Options)) (*kms.VerifyOutput, error) {
	if m.verifyFunc != nil {
		return m.verifyFunc(ctx, params, optFns...)
	}

	return nil, nil //nolint:nilnil
}

func (m *mockAWSClient) DescribeKey(ctx context.Context, params *kms.DescribeKeyInput,
	optFns ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
	if m.describeKeyFunc != nil {
		return m.describeKeyFunc(ctx, params, optFns...)
	}

	return nil, nil //nolint:nilnil
}

func (m *mockAWSClient) CreateKey(ctx context.Context, params *kms.CreateKeyInput,
	optFns ...func(*kms.Options)) (*kms.CreateKeyOutput, error) {
	if m.createKeyFunc != nil {
		return m.createKeyFunc(ctx, params, optFns...)
	}

	return nil, nil //nolint:nilnil
}

func (m *mockAWSClient) CreateAlias(ctx context.Context, params *kms.CreateAliasInput,
	optFns ...func(*kms.Options)) (*kms.CreateAliasOutput, error) {
	if m.createAliasFunc != nil {
		return m.createAliasFunc(ctx, params, optFns...)
	}

	return nil, nil //nolint:nilnil
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
