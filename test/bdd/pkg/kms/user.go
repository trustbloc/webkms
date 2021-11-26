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
	"io"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/igor-pavlenko/httpsignatures-go"
	"github.com/trustbloc/edge-core/pkg/zcapld"

	zcapld2 "github.com/trustbloc/kms/pkg/zcapld"
)

type user struct {
	name       string
	controller string
	edvDID     string

	keystoreID string
	keyID      string
	vaultID    string

	subject     string
	secretShare []byte

	recipientPubKeys map[string]*publicKeyData
	response         *response
	data             map[string]string
	multiRespStatus  []string

	signer        signer
	authKMS       kms.KeyManager
	authCrypto    crypto.Crypto
	edvCapability *zcapld.Capability
	kmsCapability *zcapld.Capability
	accessToken   string
}

type publicKeyData struct {
	rawBytes  []byte
	parsedKey *crypto.PublicKey
}

type response struct {
	status     string
	statusCode int
	headers    map[string]string
}

func (u *user) SetCapabilityInvocation(r *http.Request, action string) error {
	compressed, err := zcapld2.CompressZCAP(u.kmsCapability)
	if err != nil {
		return fmt.Errorf("failed to compress zcap: %w", err)
	}

	r.Header.Set(
		zcapld.CapabilityInvocationHTTPHeader,
		fmt.Sprintf(`zcap capability="%s",action="%s"`,
			base64.URLEncoding.EncodeToString(compressed), action),
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

func (u *user) preparePutRequest(req interface{}, endpoint string) (*http.Request, error) {
	uri := buildURI(endpoint, u.keystoreID, u.keyID)

	payload, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	request, err := http.NewRequestWithContext(context.Background(), http.MethodPut, uri, bytes.NewReader(payload))
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
	u.response = &response{
		status:     resp.Status,
		statusCode: resp.StatusCode,
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		var errResp errorResponse

		respBody, er := io.ReadAll(resp.Body)
		if er != nil {
			return fmt.Errorf("read response body: %w", er)
		}

		if err := json.Unmarshal(respBody, &errResp); err != nil {
			return fmt.Errorf("%s", respBody)
		}

		u.data = map[string]string{
			"errMessage": errResp.Message,
		}

		return fmt.Errorf("response status: %s", resp.Status)
	}

	if parsedResp == nil {
		return nil
	}

	err := json.NewDecoder(resp.Body).Decode(parsedResp)
	if err != nil {
		return fmt.Errorf("parse response: %w", err)
	}

	return nil
}

func parseRootCapability(zcap []byte) (*zcapld.Capability, error) {
	compressed, err := gzip.NewReader(bytes.NewReader(zcap))
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
