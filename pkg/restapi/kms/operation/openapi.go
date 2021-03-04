/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

// createKeystoreReq model
//
// swagger:parameters createKeystoreReq
type createKeystoreReqSpec struct { //nolint:unused,deadcode // spec
	// in: body
	// required: true
	CreateKeystoreReq createKeystoreReq
}

// createKeystoreResp model
//
// swagger:response createKeystoreResp
type createKeystoreRespSpec struct { //nolint:unused,deadcode // spec
	Location string
}

// updateCapabilityReq model
//
// swagger:parameters updateCapabilityReq
type updateCapabilityReqSpec struct { //nolint:unused,deadcode // spec
	// in: path
	// required: true
	KeystoreID string `json:"keystoreID"`
	// in: body
	// required: true
	UpdateCapabilityReq UpdateCapabilityReq
}

// createKeyReq model
//
// swagger:parameters createKeyReq
type createKeyReqSpec struct { //nolint:unused,deadcode // spec
	// in: path
	// required: true
	KeystoreID string `json:"keystoreID"`
	// in: body
	// required: true
	CreateKeyReq createKeyReq
}

// createKeyResp model
//
// swagger:response createKeyResp
type createKeyRespSpec struct { //nolint:unused,deadcode // spec
	Location string
	// in: body
	CreateKeyResp createKeyResp
}

// exportKeyReq model
//
// swagger:parameters exportKeyReq
type exportKeyReqSpec struct { //nolint:unused,deadcode // spec
	// in: path
	// required: true
	KeystoreID string `json:"keystoreID"`
	// in: path
	// required: true
	KeyID string `json:"keyID"`
}

// exportKeyResp model
//
// swagger:response exportKeyResp
type exportKeyRespSpec struct { //nolint:unused,deadcode // spec
	// in: body
	ExportKeyResp exportKeyResp
}

// importKeyReq model
//
// swagger:parameters importKeyReq
type importKeyReqSpec struct { //nolint:unused,deadcode // spec
	// in: path
	// required: true
	KeystoreID string `json:"keystoreID"`
	// in: body
	// required: true
	ImportKeyReq importKeyReq
}

// importKeyResp model
//
// swagger:response importKeyResp
type importKeyRespSpec struct { //nolint:unused,deadcode // spec
	// in: body
	ImportKeyResp importKeyResp
}

// signReq model
//
// swagger:parameters signReq
type signReqSpec struct { //nolint:unused,deadcode // spec
	// in: path
	// required: true
	KeystoreID string `json:"keystoreID"`
	// in: path
	// required: true
	KeyID string `json:"keyID"`
	// in: body
	// required: true
	SignReq signReq
}

// signResp model
//
// swagger:response signResp
type signRespSpec struct { //nolint:unused,deadcode // spec
	// in: body
	SignResp signResp
}

// verifyReq model
//
// swagger:parameters verifyReq
type verifyReqSpec struct { //nolint:unused,deadcode // spec
	// in: path
	// required: true
	KeystoreID string `json:"keystoreID"`
	// in: path
	// required: true
	KeyID string `json:"keyID"`
	// in: body
	// required: true
	VerifyReq verifyReq
}

// encryptReq model
//
// swagger:parameters encryptReq
type encryptReqSpec struct { //nolint:unused,deadcode // spec
	// in: path
	// required: true
	KeystoreID string `json:"keystoreID"`
	// in: path
	// required: true
	KeyID string `json:"keyID"`
	// in: body
	// required: true
	EncryptReq encryptReq
}

// encryptResp model
//
// swagger:parameters encryptResp
type encryptRespSpec struct { //nolint:unused,deadcode // spec
	// in: body
	EncryptResp encryptResp
}

// decryptReq model
//
// swagger:parameters decryptReq
type decryptReqSpec struct { //nolint:unused,deadcode // spec
	// in: path
	// required: true
	KeystoreID string `json:"keystoreID"`
	// in: path
	// required: true
	KeyID string `json:"keyID"`
	// in: body
	// required: true
	DecryptReq decryptReq
}

// decryptResp model
//
// swagger:parameters decryptResp
type decryptRespSpec struct { //nolint:unused,deadcode // spec
	// in: body
	DecryptResp decryptResp
}

// computeMACReq model
//
// swagger:parameters computeMACReq
type computeMACReqSpec struct { //nolint:unused,deadcode // spec
	// in: path
	// required: true
	KeystoreID string `json:"keystoreID"`
	// in: path
	// required: true
	KeyID string `json:"keyID"`
	// in: body
	// required: true
	ComputeMACReq computeMACReq
}

// computeMACResp model
//
// swagger:parameters computeMACResp
type computeMACRespSpec struct { //nolint:unused,deadcode // spec
	// in: body
	ComputeMACResp computeMACResp
}

// verifyMACReq model
//
// swagger:parameters verifyMACReq
type verifyMACReqSpec struct { //nolint:unused,deadcode // spec
	// in: path
	// required: true
	KeystoreID string `json:"keystoreID"`
	// in: path
	// required: true
	KeyID string `json:"keyID"`
	// in: body
	// required: true
	VerifyMACReq verifyMACReq
}

// wrapReq model
//
// swagger:parameters wrapReq
type wrapReqSpec struct { //nolint:unused,deadcode // spec
	// in: path
	// required: true
	KeystoreID string `json:"keystoreID"`
	// in: body
	// required: true
	WrapReq wrapReq
}

// wrapResp model
//
// swagger:parameters wrapResp
type wrapRespSpec struct { //nolint:unused,deadcode // spec
	// in: body
	WrapResp wrapResp
}

// unwrapReq model
//
// swagger:parameters unwrapReq
type unwrapReqSpec struct { //nolint:unused,deadcode // spec
	// in: path
	// required: true
	KeystoreID string `json:"keystoreID"`
	// in: path
	// required: true
	KeyID string `json:"keyID"`
	// in: body
	// required: true
	UnwrapReq unwrapReq
}

// unwrapResp model
//
// swagger:parameters unwrapResp
type unwrapRespSpec struct { //nolint:unused,deadcode // spec
	// in: body
	UnwrapResp unwrapResp
}

// easyReq model
//
// swagger:parameters easyReq
type easyReqSpec struct { //nolint:unused,deadcode // spec
	// in: path
	// required: true
	KeystoreID string `json:"keystoreID"`
	// in: path
	// required: true
	KeyID string `json:"keyID"`
	// in: body
	// required: true
	EasyReq easyReq
}

// easyResp model
//
// swagger:parameters easyResp
type easyRespSpec struct { //nolint:unused,deadcode // spec
	// in: body
	EasyResp easyResp
}

// easyOpenReq model
//
// swagger:parameters easyOpenReq
type easyOpenReqSpec struct { //nolint:unused,deadcode // spec
	// in: path
	// required: true
	KeystoreID string `json:"keystoreID"`
	// in: body
	// required: true
	EasyOpenReq easyOpenReq
}

// easyOpenResp model
//
// swagger:parameters easyOpenResp
type easyOpenRespSpec struct { //nolint:unused,deadcode // spec
	// in: body
	EasyOpenResp easyOpenResp
}

// sealOpenReq model
//
// swagger:parameters sealOpenReq
type sealOpenReqSpec struct { //nolint:unused,deadcode // spec
	// in: path
	// required: true
	KeystoreID string `json:"keystoreID"`
	// in: body
	// required: true
	SealOpenReq sealOpenReq
}

// sealOpenResp model
//
// swagger:parameters sealOpenResp
type sealOpenRespSpec struct { //nolint:unused,deadcode // spec
	// in: body
	SealOpenResp sealOpenResp
}

// signMultiReq model
//
// swagger:parameters signMultiReq
type signMultiReqSpec struct { //nolint:unused,deadcode // spec
	// in: path
	// required: true
	KeystoreID string `json:"keystoreID"`
	// in: path
	// required: true
	KeyID string `json:"keyID"`
	// in: body
	// required: true
	SignMultiReq signMultiReq
}

// verifyMultiReq model
//
// swagger:parameters verifyMultiReq
type verifyMultiReqSpec struct { //nolint:unused,deadcode // spec
	// in: path
	// required: true
	KeystoreID string `json:"keystoreID"`
	// in: path
	// required: true
	KeyID string `json:"keyID"`
	// in: body
	// required: true
	VerifyMultiReq verifyMultiReq
}

// deriveProofReq model
//
// swagger:parameters deriveProofReq
type deriveProofReqSpec struct { //nolint:unused,deadcode // spec
	// in: path
	// required: true
	KeystoreID string `json:"keystoreID"`
	// in: path
	// required: true
	KeyID string `json:"keyID"`
	// in: body
	// required: true
	DeriveProofReq deriveProofReq
}

// deriveProofResp model
//
// swagger:parameters deriveProofResp
type deriveProofRespSpec struct { //nolint:unused,deadcode // spec
	// in: body
	DeriveProofResp deriveProofResp
}

// verifyProofReq model
//
// swagger:parameters verifyProofReq
type verifyProofReqSpec struct { //nolint:unused,deadcode // spec
	// in: path
	// required: true
	KeystoreID string `json:"keystoreID"`
	// in: path
	// required: true
	KeyID string `json:"keyID"`
	// in: body
	// required: true
	VerifyProofReq verifyProofReq
}

// errorResp model
//
// swagger:response errorResp
type errorRespSpec struct { //nolint:unused,deadcode // spec
	// in: body
	ErrorResp errorResp
}

// emptyRes model
//
// swagger:response emptyRes
type emptyRes struct { //nolint:unused,deadcode // spec
}
