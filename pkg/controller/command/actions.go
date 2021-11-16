/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package command

// List of actions supported by KMS.
const (
	ActionCreateKey       = "createKey"
	ActionImportKey       = "importKey"
	ActionExportKey       = "exportKey"
	ActionSign            = "sign"
	ActionVerify          = "verify"
	ActionEncrypt         = "encrypt"
	ActionDecrypt         = "decrypt"
	ActionComputeMac      = "computeMAC"
	ActionVerifyMAC       = "verifyMAC"
	ActionSignMulti       = "signMulti"
	ActionVerifyMulti     = "verifyMulti"
	ActionDeriveProof     = "deriveProof"
	ActionVerifyProof     = "verifyProof"
	ActionEasy            = "easy"
	ActionEasyOpen        = "easyOpen"
	ActionSealOpen        = "sealOpen"
	ActionWrap            = "wrap"
	ActionUnwrap          = "unwrap"
	ActionStoreCapability = "updateEDVCapability"
)

func allActions() []string {
	return []string{
		ActionCreateKey,
		ActionExportKey,
		ActionImportKey,
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
		ActionStoreCapability,
	}
}
