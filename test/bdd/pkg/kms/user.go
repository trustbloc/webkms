/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package kms

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/igor-pavlenko/httpsignatures-go"
	"github.com/trustbloc/edge-core/pkg/zcapld"

	zcapld2 "github.com/trustbloc/hub-kms/pkg/auth/zcapld"
)

type user struct {
	name       string
	controller string

	keystoreID string
	keyID      string
	vaultID    string

	subject     string
	secretShare []byte

	recipientPubKeys map[string]*publicKeyData
	response         *response
	requestValues    map[string]string

	signer        signer
	authKMS       kms.KeyManager
	authCrypto    crypto.Crypto
	edvCapability *zcapld.Capability
	kmsCapability *zcapld.Capability
	accessToken   string
}

type publicKeyData struct {
	rawBytes  []byte
	parsedKey *publicKey
}

type response struct {
	status     string
	statusCode int
	headers    map[string]string
	body       map[string]string
}

func (u *user) SetCapabilityInvocation(r *http.Request, action string) error {
	compressed, err := zcapld2.CompressZCAP(u.kmsCapability)
	if err != nil {
		return fmt.Errorf("failed to compress zcap: %w", err)
	}

	r.Header.Set(
		zcapld.CapabilityInvocationHTTPHeader,
		fmt.Sprintf(`zcap capability="%s",action="%s"`, compressed, action),
	)

	return nil
}

func (u *user) Sign(r *http.Request) error {
	hs := httpsignatures.NewHTTPSignatures(&zcapld.AriesDIDKeySecrets{})
	hs.SetSignatureHashAlgorithm(&zcapld.AriesDIDKeySignatureHashAlgorithm{
		Crypto: u.authCrypto,
		KMS:    u.authKMS,
	})

	return hs.Sign(u.controller, r)
}

func (u *user) prepareGetRequest(endpoint string) (*http.Request, error) {
	uri := buildURI(endpoint, u.keystoreID, u.keyID)

	request, err := http.NewRequestWithContext(context.Background(), http.MethodGet, uri, nil)
	if err != nil {
		return nil, fmt.Errorf("create http request: %w", err)
	}

	return request, nil
}

func (u *user) preparePostRequest(req interface{}, endpoint string) (*http.Request, error) {
	uri := buildURI(endpoint, u.keystoreID, u.keyID)

	payload, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	request, err := http.NewRequestWithContext(context.Background(), http.MethodPost, uri, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("create http request: %w", err)
	}

	return request, nil
}

func buildURI(endpoint, keystoreID, keyID string) string {
	return strings.NewReplacer(
		"{keystoreID}", keystoreID,
		"{keyID}", keyID,
	).Replace(endpoint)
}

func (u *user) processResponse(parsedResp interface{}, resp *http.Response) error {
	keystoreID, keyID := parseLocationHeader(resp.Header)

	if keystoreID != "" {
		u.keystoreID = keystoreID
	}

	if keyID != "" {
		u.keyID = keyID
	}

	u.response = &response{
		status:     resp.Status,
		statusCode: resp.StatusCode,
	}

	kmsCapability, err := parseRootCapabilityHeader(resp.Header)
	if err != nil {
		return err
	}

	if kmsCapability != nil {
		u.kmsCapability = kmsCapability
	}

	u.response.headers = processHeaders(resp.Header)

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		var errResp errorResponse

		decodeErr := json.NewDecoder(resp.Body).Decode(&errResp)
		if decodeErr != nil {
			return fmt.Errorf("parse error response: %w", decodeErr)
		}

		u.response.body = map[string]string{
			"errMessage": errResp.Message,
		}

		return fmt.Errorf("response status: %s", resp.Status)
	}

	if parsedResp == nil {
		return nil
	}

	err = json.NewDecoder(resp.Body).Decode(parsedResp)
	if err != nil {
		return fmt.Errorf("parse response: %w", err)
	}

	return nil
}

func processHeaders(header http.Header) map[string]string {
	headers := make(map[string]string, len(header))
	for k, v := range header {
		headers[k] = v[0]
	}

	return headers
}

func parseLocationHeader(header http.Header) (string, string) {
	const (
		keystoreIDPos = 5 // https://localhost:8076/kms/keystores/{keystoreID}
		keyIDPos      = 7 // https://localhost:8076/kms/keystores/{keystoreID}/keys/{keyID}
	)

	location := header.Get("Location")
	if location == "" {
		return "", ""
	}

	s := strings.Split(location, "/")

	keystoreID := ""
	if len(s) > keystoreIDPos {
		keystoreID = s[keystoreIDPos]
	}

	keyID := ""
	if len(s) > keyIDPos {
		keyID = s[keyIDPos]
	}

	return keystoreID, keyID
}

func parseRootCapabilityHeader(header http.Header) (*zcapld.Capability, error) {
	zcap := header.Get("X-RootCapability")
	if zcap == "" {
		return nil, nil
	}

	decoded, err := base64.URLEncoding.DecodeString(zcap)
	if err != nil {
		return nil, fmt.Errorf("failed to base64URL-decode zcap: %w", err)
	}

	compressed, err := gzip.NewReader(bytes.NewReader(decoded))
	if err != nil {
		return nil, fmt.Errorf("failed to open gzip reader: %w", err)
	}

	uncompressed, err := ioutil.ReadAll(compressed)
	if err != nil {
		return nil, fmt.Errorf("failed to gunzip zcap: %w", err)
	}

	capability, err := zcapld.ParseCapability(uncompressed)
	if err != nil {
		return nil, fmt.Errorf("failed to parse rootcapability: %w", err)
	}

	return capability, nil
}
