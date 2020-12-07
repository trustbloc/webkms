/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"encoding/base64"
	"net/http"

	"github.com/gorilla/mux"
)

// swagger:route POST /kms/keystores/{keystoreID}/keys/{keyID}/easy crypto-box easyReq
//
// Encrypts (anonymously) a payload.
//
// Responses:
//        200: easyResp
//    default: errorResp
func (o *Operation) easyHandler(rw http.ResponseWriter, req *http.Request) { //nolint:dupl // readability
	kmsService, err := o.kmsServiceCreator(req)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusInternalServerError, createKMSServiceFailure, err)

		return
	}

	var request easyReq
	if ok := o.parseRequest(&request, rw, req); !ok {
		return
	}

	keystoreID := mux.Vars(req)[keystoreIDQueryParam]
	keyID := mux.Vars(req)[keyIDQueryParam]

	payload, err := base64.URLEncoding.DecodeString(request.Payload)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusBadRequest, receivedBadRequest, err)

		return
	}

	nonce, err := base64.URLEncoding.DecodeString(request.Nonce)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusBadRequest, receivedBadRequest, err)

		return
	}

	theirPub, err := base64.URLEncoding.DecodeString(request.TheirPub)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusBadRequest, receivedBadRequest, err)

		return
	}

	cipherText, err := kmsService.Easy(keystoreID, keyID, payload, nonce, theirPub)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusInternalServerError, easyMessageFailure, err)

		return
	}

	o.writeResponse(rw, easyResp{
		CipherText: base64.URLEncoding.EncodeToString(cipherText),
	})
}

// swagger:route POST /kms/keystores/{keystoreID}/easyopen crypto-box easyOpenReq
//
// Decrypts ("easy open") a payload.
//
// Responses:
//        200: easyOpenResp
//    default: errorResp
func (o *Operation) easyOpenHandler(rw http.ResponseWriter, req *http.Request) {
	kmsService, err := o.kmsServiceCreator(req)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusInternalServerError, createKMSServiceFailure, err)

		return
	}

	var request easyOpenReq
	if ok := o.parseRequest(&request, rw, req); !ok {
		return
	}

	keystoreID := mux.Vars(req)[keystoreIDQueryParam]

	cipherText, err := base64.URLEncoding.DecodeString(request.CipherText)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusBadRequest, receivedBadRequest, err)

		return
	}

	nonce, err := base64.URLEncoding.DecodeString(request.Nonce)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusBadRequest, receivedBadRequest, err)

		return
	}

	theirPub, err := base64.URLEncoding.DecodeString(request.TheirPub)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusBadRequest, receivedBadRequest, err)

		return
	}

	myPub, err := base64.URLEncoding.DecodeString(request.MyPub)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusBadRequest, receivedBadRequest, err)

		return
	}

	plainText, err := kmsService.EasyOpen(keystoreID, cipherText, nonce, theirPub, myPub)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusInternalServerError, easyOpenMessageFailure, err)

		return
	}

	o.writeResponse(rw, easyOpenResp{
		PlainText: base64.URLEncoding.EncodeToString(plainText),
	})
}

// swagger:route POST /kms/keystores/{keystoreID}/sealopen crypto-box sealOpenReq
//
// Decrypts ("seal open") a payload.
//
// Responses:
//        200: sealOpenResp
//    default: errorResp
func (o *Operation) sealOpenHandler(rw http.ResponseWriter, req *http.Request) {
	kmsService, err := o.kmsServiceCreator(req)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusInternalServerError, createKMSServiceFailure, err)

		return
	}

	var request sealOpenReq
	if ok := o.parseRequest(&request, rw, req); !ok {
		return
	}

	keystoreID := mux.Vars(req)[keystoreIDQueryParam]

	cipherText, err := base64.URLEncoding.DecodeString(request.CipherText)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusBadRequest, receivedBadRequest, err)

		return
	}

	myPub, err := base64.URLEncoding.DecodeString(request.MyPub)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusBadRequest, receivedBadRequest, err)

		return
	}

	plainText, err := kmsService.SealOpen(keystoreID, cipherText, myPub)
	if err != nil {
		o.writeErrorResponse(rw, http.StatusInternalServerError, sealOpenPayloadFailure, err)

		return
	}

	o.writeResponse(rw, sealOpenResp{
		PlainText: base64.URLEncoding.EncodeToString(plainText),
	})
}
