/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package kms

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"

	"github.com/hyperledger/aries-framework-go/pkg/kms/localkms"

	"github.com/trustbloc/kms/test/bdd/pkg/internal/cryptoutil"
)

func (s *Steps) makeEasyPayloadReq(userName, endpoint, payload, recipient string) error {
	u := s.users[userName]

	recPubKey := u.recipientPubKeys[recipient]

	recPubCurve25519, err := cryptoutil.PublicEd25519toCurve25519(recPubKey.rawBytes)
	if err != nil {
		return err
	}

	nonce := cryptoutil.GenerateNonceForCryptoBox()

	r := &easyReq{
		Payload:  base64.URLEncoding.EncodeToString([]byte(payload)),
		Nonce:    base64.URLEncoding.EncodeToString(nonce),
		TheirPub: base64.URLEncoding.EncodeToString(recPubCurve25519),
	}

	response, closeBody, err := s.makeHTTPReq(u, r, endpoint, actionEasy)
	if err != nil {
		return err
	}

	defer closeBody()

	var easyResponse easyResp

	if respErr := u.processResponse(&easyResponse, response); respErr != nil {
		return respErr
	}

	cipherText, err := base64.URLEncoding.DecodeString(easyResponse.CipherText)
	if err != nil {
		return err
	}

	u.data = map[string]string{
		"cipherText": string(cipherText),
		"nonce":      r.Nonce,
	}

	return nil
}

func (s *Steps) makeEasyOpenReq(userName, endpoint, tag, sender string) error {
	u := s.users[userName]

	cipherText := s.users[sender].data[tag]
	nonce := s.users[sender].data["nonce"]
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

	response, closeBody, err := s.makeHTTPReq(u, r, endpoint, actionEasyOpen)
	if err != nil {
		return err
	}

	defer closeBody()

	var easyOpenResponse easyOpenResp

	if respErr := u.processResponse(&easyOpenResponse, response); respErr != nil {
		return respErr
	}

	plainText, err := base64.URLEncoding.DecodeString(easyOpenResponse.PlainText)
	if err != nil {
		return err
	}

	u.data = map[string]string{
		"plainText": string(plainText),
	}

	return nil
}

func (s *Steps) sealPayloadForRecipient(userName, payload, recipient string) error {
	u := s.users[userName]

	cb, err := localkms.NewCryptoBox(&localkms.LocalKMS{}) // "Seal" doesn't use functionality of local KMS
	if err != nil {
		return err
	}

	theirPub := u.recipientPubKeys[recipient].rawBytes

	theirPubCurve25519, err := cryptoutil.PublicEd25519toCurve25519(theirPub)
	if err != nil {
		return err
	}

	cipherText, err := cb.Seal([]byte(payload), theirPubCurve25519, rand.Reader)
	if err != nil {
		return err
	}

	u.data = map[string]string{
		"cipherText": string(cipherText),
	}

	return nil
}

func (s *Steps) makeSealOpenReq(userName, endpoint, tag, sender string) error {
	u := s.users[userName]

	cipherText := s.users[sender].data[tag]
	myPub := s.users[sender].recipientPubKeys[userName].rawBytes

	r := &sealOpenReq{
		CipherText: base64.URLEncoding.EncodeToString([]byte(cipherText)),
		MyPub:      base64.URLEncoding.EncodeToString(myPub),
	}

	response, closeBody, err := s.makeHTTPReq(u, r, endpoint, actionSealOpen)
	if err != nil {
		return err
	}

	defer closeBody()

	var sealOpenResponse sealOpenResp

	if respErr := u.processResponse(&sealOpenResponse, response); respErr != nil {
		return respErr
	}

	plainText, err := base64.URLEncoding.DecodeString(sealOpenResponse.PlainText)
	if err != nil {
		return err
	}

	u.data = map[string]string{
		"plainText": string(plainText),
	}

	return nil
}

func (s *Steps) makeHTTPReq(u *user, req interface{}, endpoint, action string) (*http.Response, func(), error) {
	request, err := u.preparePostRequest(req, endpoint)
	if err != nil {
		return nil, nil, fmt.Errorf("prepare POST request: %w", err)
	}

	err = u.SetCapabilityInvocation(request, action)
	if err != nil {
		return nil, nil, fmt.Errorf("user failed to set zcap: %w", err)
	}

	err = u.Sign(request)
	if err != nil {
		return nil, nil, fmt.Errorf("user failed to sign request: %w", err)
	}

	response, err := s.httpClient.Do(request)
	if err != nil {
		return nil, nil, fmt.Errorf("do HTTP request: %w", err)
	}

	closeBody := func() {
		closeErr := response.Body.Close()
		if closeErr != nil {
			s.logger.Errorf("Failed to close response body: %s\n", closeErr.Error())
		}
	}

	return response, closeBody, nil
}
