/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package kms

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
)

type user struct {
	name             string
	controller       string
	keystoreID       string
	keyID            string
	vaultID          string
	recipientPubKeys map[string]publicKeyWithBytesXY
	response         *response
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

	u.processHeaders(resp.Header)

	if parsedResp == nil {
		return nil
	}

	return processBody(parsedResp, resp.Body)
}

func (u *user) processHeaders(header http.Header) {
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

	h := make(map[string]string, len(header))
	for k, v := range header {
		h[k] = v[0]
	}

	u.response.headers = h
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
	err := json.NewDecoder(body).Decode(&parsedResp)
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}

	return nil
}
