/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package aws

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
	arieskms "github.com/hyperledger/aries-framework-go/pkg/kms"
)

type awsClient interface {
	Sign(input *kms.SignInput) (*kms.SignOutput, error)
	GetPublicKey(input *kms.GetPublicKeyInput) (*kms.GetPublicKeyOutput, error)
	Verify(input *kms.VerifyInput) (*kms.VerifyOutput, error)
	DescribeKey(input *kms.DescribeKeyInput) (*kms.DescribeKeyOutput, error)
	CreateKeyRequest(input *kms.CreateKeyInput) (req *request.Request, output *kms.CreateKeyOutput)
}

type metricsProvider interface {
	SignCount()
	SignTime(value time.Duration)
	ExportPublicKeyCount()
	ExportPublicKeyTime(value time.Duration)
	VerifyCount()
	VerifyTime(value time.Duration)
}

// Service aws kms.
type Service struct {
	client           awsClient
	metrics          metricsProvider
	healthCheckKeyID string
}

// nolint: gochecknoglobals
var kmsKeyTypes = map[string]arieskms.KeyType{
	"ECDSA_SHA_256": arieskms.ECDSAP256DER,
	"ECDSA_SHA_384": arieskms.ECDSAP384DER,
	"ECDSA_SHA_521": arieskms.ECDSAP521DER,
}

// New return aws service.
func New(awsSession *session.Session, metrics metricsProvider, healthCheckKeyID string) *Service {
	return &Service{client: kms.New(awsSession), metrics: metrics, healthCheckKeyID: healthCheckKeyID}
}

// Sign data.
func (s *Service) Sign(msg []byte, kh interface{}) ([]byte, error) {
	startTime := time.Now()

	defer func() {
		s.metrics.SignTime(time.Since(startTime))
	}()

	s.metrics.SignCount()

	keyID, err := getKeyID(kh.(string))
	if err != nil {
		return nil, err
	}

	input := &kms.SignInput{
		KeyId:            aws.String(keyID),
		Message:          msg,
		MessageType:      aws.String("RAW"),
		SigningAlgorithm: aws.String("ECDSA_SHA_256"),
	}

	result, err := s.client.Sign(input)
	if err != nil {
		return nil, err
	}

	return result.Signature, nil
}

// Get key handle.
func (s *Service) Get(keyID string) (interface{}, error) {
	return keyID, nil
}

// HealthCheck check kms.
func (s *Service) HealthCheck() error {
	keyID, err := getKeyID(s.healthCheckKeyID)
	if err != nil {
		return err
	}

	_, err = s.client.DescribeKey(&kms.DescribeKeyInput{KeyId: &keyID})
	if err != nil {
		return err
	}

	return nil
}

// ExportPubKeyBytes export public key.
func (s *Service) ExportPubKeyBytes(keyURI string) ([]byte, arieskms.KeyType, error) {
	startTime := time.Now()

	defer func() {
		s.metrics.ExportPublicKeyTime(time.Since(startTime))
	}()

	s.metrics.ExportPublicKeyCount()

	keyID, err := getKeyID(keyURI)
	if err != nil {
		return nil, "", err
	}

	input := &kms.GetPublicKeyInput{
		KeyId: aws.String(keyID),
	}

	result, err := s.client.GetPublicKey(input)
	if err != nil {
		return nil, "", err
	}

	return result.PublicKey, kmsKeyTypes[*result.SigningAlgorithms[0]], nil
}

// Verify signature.
func (s *Service) Verify(signature, msg []byte, kh interface{}) error {
	startTime := time.Now()

	defer func() {
		s.metrics.VerifyTime(time.Since(startTime))
	}()

	s.metrics.VerifyCount()

	keyID, err := getKeyID(kh.(string))
	if err != nil {
		return err
	}

	input := &kms.VerifyInput{
		KeyId:            aws.String(keyID),
		Message:          msg,
		MessageType:      aws.String("RAW"),
		Signature:        signature,
		SigningAlgorithm: aws.String("ECDSA_SHA_256"),
	}

	_, err = s.client.Verify(input)

	return err
}

// Create key.
func (s *Service) Create(kt arieskms.KeyType) (string, interface{}, error) {
	keyUsage := kms.KeyUsageTypeSignVerify

	keySpec := ""

	switch string(kt) {
	case arieskms.ECDSAP256DER, arieskms.NISTP256ECDHKW:
		keySpec = kms.KeySpecEccNistP256
	case arieskms.ECDSAP384DER, arieskms.NISTP384ECDHKW:
		keySpec = kms.KeySpecEccNistP384
	case arieskms.ECDSAP521DER, arieskms.NISTP521ECDHKW:
		keySpec = kms.KeySpecEccNistP521
	default:
		return "", nil, fmt.Errorf("key not supported %s", kt)
	}

	_, result := s.client.CreateKeyRequest(&kms.CreateKeyInput{KeySpec: &keySpec, KeyUsage: &keyUsage})

	return *result.KeyMetadata.KeyId, *result.KeyMetadata.KeyId, nil
}

// ImportPrivateKey private key.
func (s *Service) ImportPrivateKey(privKey interface{}, kt arieskms.KeyType,
	opts ...arieskms.PrivateKeyOpts) (string, interface{}, error) {
	return "", nil, fmt.Errorf("not implemented")
}

func getKeyID(keyURI string) (string, error) {
	// keyURI must have the following format: 'aws-kms://arn:<partition>:kms:<region>:[:path]'.
	// See http://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html.
	re1 := regexp.MustCompile(`aws-kms://arn:(aws[a-zA-Z0-9-_]*):kms:([a-z0-9-]+):([a-z0-9-]+):key/(.+)`)

	if strings.Contains(keyURI, "alias") {
		re1 = regexp.MustCompile(`aws-kms://arn:(aws[a-zA-Z0-9-_]*):kms:([a-z0-9-]+):([a-z0-9-]+):(.+)`)
	}

	r := re1.FindStringSubmatch(keyURI)

	const subStringCount = 5

	if len(r) != subStringCount {
		return "", fmt.Errorf("extracting key id from URI failed")
	}

	return r[4], nil
}
