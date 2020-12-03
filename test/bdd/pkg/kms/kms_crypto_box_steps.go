/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package kms

import (
	"encoding/base64"
	"fmt"

	"github.com/trustbloc/hub-kms/test/bdd/pkg/internal/cryptoutil"
)

func (s *Steps) makeEasyPayloadReq(userName, endpoint, payload, recipient string) error { //nolint:funlen // ignore
	u := s.users[userName]

	recipientPubKey := u.recipientPubKeys[recipient]

	recPubCurve25519, err := cryptoutil.PublicEd25519toCurve25519(recipientPubKey.rawBytes)
	if err != nil {
		return err
	}

	nonce := cryptoutil.GenerateNonceForCryptoBox()
	encodedNonce := base64.URLEncoding.EncodeToString(nonce)

	u.requestValues = map[string]string{"nonce": encodedNonce}

	r := &easyReq{
		Payload:  base64.URLEncoding.EncodeToString([]byte(payload)),
		Nonce:    encodedNonce,
		TheirPub: base64.URLEncoding.EncodeToString(recPubCurve25519),
	}

	request, err := u.preparePostRequest(r, endpoint)
	if err != nil {
		return err
	}

	err = u.SetCapabilityInvocation(request, actionEasy)
	if err != nil {
		return fmt.Errorf("user failed to set zcap: %w", err)
	}

	err = u.Sign(request)
	if err != nil {
		return fmt.Errorf("user failed to sign request: %w", err)
	}

	response, err := s.httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("http do: %w", err)
	}

	defer func() {
		closeErr := response.Body.Close()
		if closeErr != nil {
			s.logger.Errorf("Failed to close response body: %s\n", closeErr.Error())
		}
	}()

	var easyResponse easyResp

	if respErr := u.processResponse(&easyResponse, response); respErr != nil {
		return respErr
	}

	cipherText, err := base64.URLEncoding.DecodeString(easyResponse.CipherText)
	if err != nil {
		return err
	}

	u.response.body = map[string]string{
		"cipherText": string(cipherText),
	}

	return nil
}

func (s *Steps) makeEasyOpenReq(userName, endpoint, tag, sender string) error { //nolint:funlen // ignoreg
	u := s.users[userName]

	cipherText := s.users[sender].response.body[tag]
	nonce := s.users[sender].requestValues["nonce"]
	myPub := s.users[sender].recipientPubKeys[userName].rawBytes

	theirPub := u.recipientPubKeys[sender].rawBytes

	theirPubCurve25519, err := cryptoutil.PublicEd25519toCurve25519(theirPub)
	if err != nil {
		return err
	}

	r := &easyOpenReq{
		CipherText: base64.URLEncoding.EncodeToString([]byte(cipherText)),
		Nonce:      nonce,
		TheirPub:   base64.URLEncoding.EncodeToString(theirPubCurve25519),
		MyPub:      base64.URLEncoding.EncodeToString(myPub),
	}

	request, err := u.preparePostRequest(r, endpoint)
	if err != nil {
		return err
	}

	err = u.SetCapabilityInvocation(request, actionEasyOpen)
	if err != nil {
		return fmt.Errorf("user failed to set zcap: %w", err)
	}

	err = u.Sign(request)
	if err != nil {
		return fmt.Errorf("user failed to sign request: %w", err)
	}

	response, err := s.httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("http do: %w", err)
	}

	defer func() {
		closeErr := response.Body.Close()
		if closeErr != nil {
			s.logger.Errorf("Failed to close response body: %s\n", closeErr.Error())
		}
	}()

	var easyOpenResponse easyOpenResp

	if respErr := u.processResponse(&easyOpenResponse, response); respErr != nil {
		return respErr
	}

	plainText, err := base64.URLEncoding.DecodeString(easyOpenResponse.PlainText)
	if err != nil {
		return err
	}

	u.response.body = map[string]string{
		"plainText": string(plainText),
	}

	return nil
}
