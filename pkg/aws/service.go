/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package aws

import (
	"crypto/elliptic"
	"crypto/sha512"
	"encoding/asn1"
	"fmt"
	"hash"
	"math/big"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/btcsuite/btcd/btcec"
	arieskms "github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/minio/sha256-simd"
)

type awsClient interface {
	Sign(input *kms.SignInput) (*kms.SignOutput, error)
	GetPublicKey(input *kms.GetPublicKeyInput) (*kms.GetPublicKeyOutput, error)
	Verify(input *kms.VerifyInput) (*kms.VerifyOutput, error)
	DescribeKey(input *kms.DescribeKeyInput) (*kms.DescribeKeyOutput, error)
	CreateKey(input *kms.CreateKeyInput) (*kms.CreateKeyOutput, error)
}

type metricsProvider interface {
	SignCount()
	SignTime(value time.Duration)
	ExportPublicKeyCount()
	ExportPublicKeyTime(value time.Duration)
	VerifyCount()
	VerifyTime(value time.Duration)
}

type ecdsaSignature struct {
	R, S *big.Int
}

// Service aws kms.
type Service struct {
	client           awsClient
	metrics          metricsProvider
	healthCheckKeyID string
}

const (
	signingAlgorithmEcdsaSha256 = "ECDSA_SHA_256"
	signingAlgorithmEcdsaSha384 = "ECDSA_SHA_384"
	signingAlgorithmEcdsaSha512 = "ECDSA_SHA_512"
	bitSize                     = 8
)

// nolint: gochecknoglobals
var kmsKeyTypes = map[string]arieskms.KeyType{
	signingAlgorithmEcdsaSha256: arieskms.ECDSAP256DER,
	signingAlgorithmEcdsaSha384: arieskms.ECDSAP384DER,
	signingAlgorithmEcdsaSha512: arieskms.ECDSAP521DER,
}

// nolint: gochecknoglobals
var keySpecToCurve = map[string]elliptic.Curve{
	kms.KeySpecEccSecgP256k1: btcec.S256(),
}

// New return aws service.
func New(awsSession *session.Session, metrics metricsProvider, healthCheckKeyID string) *Service {
	return &Service{client: kms.New(awsSession), metrics: metrics, healthCheckKeyID: healthCheckKeyID}
}

// Sign data.
func (s *Service) Sign(msg []byte, kh interface{}) ([]byte, error) { //nolint: funlen
	startTime := time.Now()

	defer func() {
		if s.metrics != nil {
			s.metrics.SignTime(time.Since(startTime))
		}
	}()

	if s.metrics != nil {
		s.metrics.SignCount()
	}

	keyID, err := getKeyID(kh.(string))
	if err != nil {
		return nil, err
	}

	describeKey, err := s.client.DescribeKey(&kms.DescribeKeyInput{KeyId: &keyID})
	if err != nil {
		return nil, err
	}

	digest, err := hashMessage(msg, *describeKey.KeyMetadata.SigningAlgorithms[0])
	if err != nil {
		return nil, err
	}

	input := &kms.SignInput{
		KeyId:            aws.String(keyID),
		Message:          digest,
		MessageType:      aws.String("DIGEST"),
		SigningAlgorithm: describeKey.KeyMetadata.SigningAlgorithms[0],
	}

	result, err := s.client.Sign(input)
	if err != nil {
		return nil, err
	}

	if *describeKey.KeyMetadata.KeySpec == kms.KeySpecEccSecgP256k1 {
		signature := ecdsaSignature{}

		_, err = asn1.Unmarshal(result.Signature, &signature)
		if err != nil {
			return nil, err
		}

		curveBits := keySpecToCurve[*describeKey.KeyMetadata.KeySpec].Params().BitSize

		keyBytes := curveBits / bitSize
		if curveBits%bitSize > 0 {
			keyBytes++
		}

		copyPadded := func(source []byte, size int) []byte {
			dest := make([]byte, size)
			copy(dest[size-len(source):], source)

			return dest
		}

		return append(copyPadded(signature.R.Bytes(), keyBytes), copyPadded(signature.S.Bytes(), keyBytes)...), nil
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
		if s.metrics != nil {
			s.metrics.ExportPublicKeyTime(time.Since(startTime))
		}
	}()

	if s.metrics != nil {
		s.metrics.ExportPublicKeyCount()
	}

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
	return fmt.Errorf("not implemented")
}

// Create key.
func (s *Service) Create(kt arieskms.KeyType) (string, interface{}, error) {
	keyUsage := kms.KeyUsageTypeSignVerify

	keySpec := ""

	switch string(kt) {
	case arieskms.ECDSAP256DER:
		keySpec = kms.KeySpecEccNistP256
	case arieskms.ECDSAP384DER:
		keySpec = kms.KeySpecEccNistP384
	case arieskms.ECDSAP521DER:
		keySpec = kms.KeySpecEccNistP521
	case arieskms.ECDSASecp256k1IEEEP1363:
		keySpec = kms.KeySpecEccSecgP256k1
	default:
		return "", nil, fmt.Errorf("key not supported %s", kt)
	}

	result, err := s.client.CreateKey(&kms.CreateKeyInput{KeySpec: &keySpec, KeyUsage: &keyUsage})
	if err != nil {
		return "", nil, err
	}

	return *result.KeyMetadata.KeyId, *result.KeyMetadata.KeyId, nil
}

// CreateAndExportPubKeyBytes create and export key.
func (s *Service) CreateAndExportPubKeyBytes(kt arieskms.KeyType, opts ...arieskms.KeyOpts) (string, []byte, error) {
	keyID, _, err := s.Create(kt)
	if err != nil {
		return "", nil, err
	}

	pubKeyBytes, _, err := s.ExportPubKeyBytes(keyID)
	if err != nil {
		return "", nil, err
	}

	return keyID, pubKeyBytes, nil
}

// ImportPrivateKey private key.
func (s *Service) ImportPrivateKey(privKey interface{}, kt arieskms.KeyType,
	opts ...arieskms.PrivateKeyOpts) (string, interface{}, error) {
	return "", nil, fmt.Errorf("not implemented")
}

// SignMulti sign multi.
func (s *Service) SignMulti(messages [][]byte, kh interface{}) ([]byte, error) {
	return nil, fmt.Errorf("not implemented")
}

func getKeyID(keyURI string) (string, error) {
	if !strings.Contains(keyURI, "aws-kms") {
		return keyURI, nil
	}

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

func hashMessage(message []byte, algorithm string) ([]byte, error) {
	var digest hash.Hash

	switch algorithm {
	case signingAlgorithmEcdsaSha256:
		digest = sha256.New()
	case signingAlgorithmEcdsaSha384:
		digest = sha512.New384()
	case signingAlgorithmEcdsaSha512:
		digest = sha512.New()
	default:
		return []byte{}, fmt.Errorf("unknown signing algorithm")
	}

	digest.Write(message)

	return digest.Sum(nil), nil
}
