/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package kms

import (
	"bytes"
	"compress/gzip"
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

	zcapld2 "github.com/trustbloc/hub-kms/pkg/auth/zcapld"
)

type signer interface {
	// Sign will sign document and return signature
	Sign(data []byte) ([]byte, error)
}

type user struct {
	name             string
	controller       string
	keystoreID       string
	edvCapability    *zcapld.Capability
	signer           signer
	keyID            string
	vaultID          string
	recipientPubKeys map[string]publicKeyWithBytesXY
	response         *response
	kmsCapability    *zcapld.Capability
	authKMS          kms.KeyManager
	authCrypto       crypto.Crypto
}

type response struct {
	status  string
	headers map[string]string
	body    map[string]string
}

func (u *user) processResponse(parsedResp interface{}, resp *http.Response) error {
	u.response = &response{
		status: resp.Status,
	}

	err := u.processHeaders(resp.Header)
	if err != nil {
		return fmt.Errorf("failed to process headers: %w", err)
	}

	if parsedResp == nil {
		return nil
	}

	return processBody(parsedResp, resp.Body)
}

func (u *user) processHeaders(header http.Header) error {
	loc := header.Get("Location")
	if loc != "" {
		keystoreID, keyID := parseLocation(loc)

		if keystoreID != "" {
			u.keystoreID = keystoreID
		}

		if keyID != "" {
			u.keyID = keyID
		}
	}

	zcap := header.Get("X-RootCapability")
	if zcap != "" {
		decoded, err := base64.URLEncoding.DecodeString(zcap)
		if err != nil {
			return fmt.Errorf("failed to base64URL-decode zcap: %w", err)
		}

		compressed, err := gzip.NewReader(bytes.NewReader(decoded))
		if err != nil {
			return fmt.Errorf("failed to open gzip reader: %w", err)
		}

		uncompressed, err := ioutil.ReadAll(compressed)
		if err != nil {
			return fmt.Errorf("failed to gunzip zcap: %w", err)
		}

		u.kmsCapability, err = zcapld.ParseCapability(uncompressed)
		if err != nil {
			return fmt.Errorf("failed to parse rootcapability: %w", err)
		}
	}

	h := make(map[string]string, len(header))
	for k, v := range header {
		h[k] = v[0]
	}

	u.response.headers = h

	return nil
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

func parseLocation(location string) (string, string) {
	const (
		keystoreIDPos = 3 // localhost:8076/kms/keystores/{keystoreID}
		keyIDPos      = 5 // localhost:8076/kms/keystores/{keystoreID}/keys/{keyID}
	)

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

func processBody(parsedResp interface{}, body io.ReadCloser) error {
	contents, err := ioutil.ReadAll(body)
	if err != nil {
		return fmt.Errorf("failed to read body: %w", err)
	}

	err = json.Unmarshal(contents, parsedResp)
	if err != nil {
		return fmt.Errorf("failed to unmarshal response body '%s': %w", contents, err)
	}

	return nil
}
