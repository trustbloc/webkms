package aws

import (
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/google/tink/go/core/registry"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock"
)

type awsProvider interface {
	NewSession(region string) (*session.Session, error)
	NewClient(uriPrefix string, session *session.Session) (registry.KMSClient, error)
}

type awsSecretLock struct {
	kmsClient registry.KMSClient
	keyURI    string
}

// New returns a new secret lock service that uses AWS to encrypt keys.
func New(keyURI string, provider awsProvider) (secretlock.Service, error) {
	region, err := getRegion(keyURI)
	if err != nil {
		return nil, err
	}

	sess, err := provider.NewSession(region)
	if err != nil {
		return nil, err
	}

	kms, err := provider.NewClient(keyURI, sess)
	if err != nil {
		return nil, err
	}

	return &awsSecretLock{
		kmsClient: kms,
		keyURI:    keyURI,
	}, nil
}

func (a *awsSecretLock) Encrypt(_ string, req *secretlock.EncryptRequest) (*secretlock.EncryptResponse, error) {
	aead, err := a.kmsClient.GetAEAD(a.keyURI)
	if err != nil {
		return nil, fmt.Errorf("encrypt: %w", err)
	}

	ct, err := aead.Encrypt([]byte(req.Plaintext), []byte(req.AdditionalAuthenticatedData))
	if err != nil {
		return nil, fmt.Errorf("encrypt: %w", err)
	}

	return &secretlock.EncryptResponse{
		Ciphertext: base64.URLEncoding.EncodeToString(ct),
	}, nil
}

func (a *awsSecretLock) Decrypt(_ string, req *secretlock.DecryptRequest) (*secretlock.DecryptResponse, error) {
	decoded, err := base64.URLEncoding.DecodeString(req.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decode ciphertext: %w", err)
	}

	aead, err := a.kmsClient.GetAEAD(a.keyURI)
	if err != nil {
		return nil, fmt.Errorf("decrypt ciphertext: %w", err)
	}

	pt, err := aead.Decrypt(decoded, []byte(req.AdditionalAuthenticatedData))
	if err != nil {
		return nil, fmt.Errorf("decrypt ciphertext: %w", err)
	}

	return &secretlock.DecryptResponse{Plaintext: string(pt)}, nil
}

func getRegion(keyURI string) (string, error) {
	// keyURI must have the following format: 'aws-kms://arn:<partition>:kms:<region>:[:path]'.
	// See http://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html.
	re1 := regexp.MustCompile(`aws-kms://arn:(aws[a-zA-Z0-9-_]*):kms:([a-z0-9-]+):`)

	r := re1.FindStringSubmatch(keyURI)

	const subStringCount = 3

	if len(r) != subStringCount {
		return "", errors.New("extracting region from URI failed")
	}

	return r[2], nil
}
