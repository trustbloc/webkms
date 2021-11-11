package aws_test

import (
	"encoding/base64"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/testutil"
	"github.com/google/tink/go/tink"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock"
	"github.com/stretchr/testify/require"

	awssecretlock "github.com/trustbloc/kms/pkg/secretlock/aws"
)

const keyURI = "aws-kms://arn:aws:kms:mock-region:235739564943:key/3ee50705-5a82-4f5b-9753-05c4f473922f"

func TestSign(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		awsSession, err := session.NewSession(&aws.Config{
			Credentials: credentials.NewStaticCredentials("AKID", "SECRET", "SESSION"),
			Region:      aws.String("mock-region"),
			SleepDelay:  func(time.Duration) {},
		})

		require.NotNil(t, awsSession)
		require.NoError(t, err)

		provider := &mockProvider{
			Session: awsSession,
			Client:  &testutil.DummyKMSClient{},
		}

		secretLock, err := awssecretlock.New(keyURI, provider)

		require.NotNil(t, secretLock)
		require.NoError(t, err)

		response, err := secretLock.Encrypt(keyURI, &secretlock.EncryptRequest{
			Plaintext:                   "Test",
			AdditionalAuthenticatedData: "",
		})

		require.NoError(t, err)

		_, err = secretLock.Decrypt(keyURI, &secretlock.DecryptRequest{
			Ciphertext:                  response.Ciphertext,
			AdditionalAuthenticatedData: "",
		})

		require.NoError(t, err)
	})

	t.Run("Bad key uri error", func(t *testing.T) {
		awsSession, err := session.NewSession(&aws.Config{
			Credentials: credentials.NewStaticCredentials("AKID", "SECRET", "SESSION"),
			Region:      aws.String("mock-region"),
			SleepDelay:  func(time.Duration) {},
		})

		require.NotNil(t, awsSession)
		require.NoError(t, err)

		provider := &mockProvider{
			Session: awsSession,
			Client:  &testutil.DummyKMSClient{},
		}

		secretLock, err := awssecretlock.New("invalid", provider)

		require.Nil(t, secretLock)
		require.EqualError(t, err, "extracting region from URI failed")
	})

	t.Run("NewSession failed", func(t *testing.T) {
		sessionErrorText := "NewSession failed"

		provider := &mockProvider{
			SessionError: errors.New(sessionErrorText),
			Client:       &testutil.DummyKMSClient{},
		}

		secretLock, err := awssecretlock.New(keyURI, provider)

		require.Nil(t, secretLock)
		require.EqualError(t, err, sessionErrorText)
	})

	t.Run("NewClient failed", func(t *testing.T) {
		newClientErrorText := "NewClient failed"

		awsSession, err := session.NewSession(&aws.Config{
			Credentials: credentials.NewStaticCredentials("AKID", "SECRET", "SESSION"),
			Region:      aws.String("mock-region"),
			SleepDelay:  func(time.Duration) {},
		})

		require.NotNil(t, awsSession)
		require.NoError(t, err)

		provider := &mockProvider{
			Session:     awsSession,
			ClientError: errors.New(newClientErrorText),
		}

		secretLock, err := awssecretlock.New(keyURI, provider)

		require.Nil(t, secretLock)
		require.EqualError(t, err, newClientErrorText)
	})

	t.Run("GetAEAD failed", func(t *testing.T) {
		GetAEADErrorText := "GetAEAD failed"

		awsSession, err := session.NewSession(&aws.Config{
			Credentials: credentials.NewStaticCredentials("AKID", "SECRET", "SESSION"),
			Region:      aws.String("mock-region"),
			SleepDelay:  func(time.Duration) {},
		})

		require.NotNil(t, awsSession)
		require.NoError(t, err)

		provider := &mockProvider{
			Session: awsSession,
			Client: &mockKMSClient{
				AEADError: errors.New(GetAEADErrorText),
			},
		}

		secretLock, err := awssecretlock.New(keyURI, provider)

		require.NotNil(t, secretLock)
		require.NoError(t, err)

		_, err = secretLock.Encrypt(keyURI, &secretlock.EncryptRequest{
			Plaintext:                   "Test",
			AdditionalAuthenticatedData: "",
		})

		require.EqualError(t, err, fmt.Sprintf("encrypt: %s", GetAEADErrorText))

		_, err = secretLock.Decrypt(keyURI, &secretlock.DecryptRequest{
			Ciphertext:                  base64.URLEncoding.EncodeToString([]byte("{}")),
			AdditionalAuthenticatedData: "",
		})

		require.EqualError(t, err, fmt.Sprintf("decrypt ciphertext: %s", GetAEADErrorText))

		_, err = secretLock.Decrypt(keyURI, &secretlock.DecryptRequest{
			Ciphertext:                  "!invalid",
			AdditionalAuthenticatedData: "",
		})

		require.EqualError(t, err, fmt.Sprintf("decode ciphertext: %s", "illegal base64 data at input byte 0"))
	})

	t.Run("Encrypt/Decrypt failed", func(t *testing.T) {
		encryptError := "encrypt failed"
		decryptError := "decrypt failed"

		awsSession, err := session.NewSession(&aws.Config{
			Credentials: credentials.NewStaticCredentials("AKID", "SECRET", "SESSION"),
			Region:      aws.String("mock-region"),
			SleepDelay:  func(time.Duration) {},
		})

		require.NotNil(t, awsSession)
		require.NoError(t, err)

		provider := &mockProvider{
			Session: awsSession,
			Client: &mockKMSClient{
				AEAD: &mockAEADErrors{
					EncryptError: errors.New(encryptError),
					DecryptError: errors.New(decryptError),
				},
			},
		}

		secretLock, err := awssecretlock.New(keyURI, provider)

		require.NotNil(t, secretLock)
		require.NoError(t, err)

		_, err = secretLock.Encrypt(keyURI, &secretlock.EncryptRequest{
			Plaintext:                   "Test",
			AdditionalAuthenticatedData: "",
		})

		require.EqualError(t, err, fmt.Sprintf("encrypt: %s", encryptError))

		_, err = secretLock.Decrypt(keyURI, &secretlock.DecryptRequest{
			Ciphertext:                  base64.URLEncoding.EncodeToString([]byte("{}")),
			AdditionalAuthenticatedData: "",
		})

		require.EqualError(t, err, fmt.Sprintf("decrypt ciphertext: %s", decryptError))
	})
}

// Provider mock AWS functionality.
type mockProvider struct {
	Session      *session.Session
	SessionError error
	Client       registry.KMSClient
	ClientError  error
}

// NewSession returns mock session.
func (p *mockProvider) NewSession(region string) (*session.Session, error) {
	return p.Session, p.SessionError
}

// NewClient returns mock client.
func (p *mockProvider) NewClient(uriPrefix string, sess *session.Session) (registry.KMSClient, error) {
	return p.Client, p.ClientError
}

type mockKMSClient struct {
	SupportedKey string
	AEAD         tink.AEAD
	AEADError    error
}

func (m *mockKMSClient) Supported(keyURI string) bool {
	return keyURI == m.SupportedKey
}

func (m *mockKMSClient) GetAEAD(keyURI string) (tink.AEAD, error) {
	return m.AEAD, m.AEADError
}

type mockAEADErrors struct {
	EncryptError error
	DecryptError error
}

func (m *mockAEADErrors) Encrypt(plaintext, additionalData []byte) ([]byte, error) {
	return nil, m.EncryptError
}

func (m *mockAEADErrors) Decrypt(ciphertext, additionalData []byte) ([]byte, error) {
	return nil, m.DecryptError
}
