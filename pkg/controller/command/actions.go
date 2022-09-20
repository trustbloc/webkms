/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package command

// List of actions supported by KMS.
const (
	ActionCreateKeyStore   = "createKeyStore"
	ActionCreateKey        = "createKey"
	ActionImportKey        = "importKey"
	ActionExportKey        = "exportKey"
	ActionRotateKey        = "rotateKey"
	ActionSign             = "sign"
	ActionVerify           = "verify"
	ActionEncrypt          = "encrypt"
	ActionDecrypt          = "decrypt"
	ActionComputeMac       = "computeMAC"
	ActionVerifyMAC        = "verifyMAC"
	ActionSignMulti        = "signMulti"
	ActionVerifyMulti      = "verifyMulti"
	ActionDeriveProof      = "deriveProof"
	ActionVerifyProof      = "verifyProof"
	ActionEasy             = "easy"
	ActionEasyOpen         = "easyOpen"
	ActionSealOpen         = "sealOpen"
	ActionWrap             = "wrap"
	ActionUnwrap           = "unwrap"
	ActionBlind            = "blind"
	ActionCorrectnessProof = "correctnessProof"
	ActionSignWithSecrets  = "signWithSecrets"
)

func allActions() []string {
	return []string{
		ActionCreateKey,
		ActionExportKey,
		ActionImportKey,
		ActionRotateKey,
		ActionSign,
		ActionVerify,
		ActionComputeMac,
		ActionVerifyMAC,
		ActionEncrypt,
		ActionDecrypt,
		ActionEasy,
		ActionEasyOpen,
		ActionSealOpen,
		ActionSignMulti,
		ActionVerifyMulti,
		ActionDeriveProof,
		ActionVerifyProof,
		ActionWrap,
		ActionUnwrap,
		ActionBlind,
		ActionCorrectnessProof,
		ActionSignWithSecrets,
	}
}
