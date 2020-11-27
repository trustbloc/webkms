/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package kms

import (
	"encoding/json"
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/ed25519signature2018"
	"github.com/trustbloc/edge-core/pkg/zcapld"

	"github.com/trustbloc/hub-kms/pkg/restapi/kms/operation"
)

const (
	edvResource     = "urn:edv:vault"
	edvDIDKeyHeader = "Edvdidkey"
)

const (
	actionCreateKey       = "createKey"
	actionExportKey       = "exportKey"
	actionSign            = "sign"
	actionVerify          = "verify"
	actionWrap            = "wrap"
	actionUnwrap          = "unwrap"
	actionComputeMac      = "computeMAC"
	actionVerifyMAC       = "verifyMAC"
	actionEncrypt         = "encrypt"
	actionDecrypt         = "decrypt"
	actionStoreCapability = "updateEDVCapability"
)

func (s *Steps) updateCapability(u *user) error {
	// create chain capability
	chainCapability, err := s.createChainCapability(u)
	if err != nil {
		return err
	}

	chainCapabilityBytes, err := json.Marshal(chainCapability)
	if err != nil {
		return err
	}

	r := &operation.UpdateCapabilityReq{
		EDVCapability: chainCapabilityBytes,
	}

	request, err := u.preparePostRequest(r, s.bddContext.KeyServerURL+capabilityEndpoint)
	if err != nil {
		return err
	}

	err = u.SetCapabilityInvocation(request, actionStoreCapability)
	if err != nil {
		return fmt.Errorf("user failed to set capability: %w", err)
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

	return u.processResponse(nil, response)
}

func (s *Steps) createChainCapability(u *user) (*zcapld.Capability, error) {
	return zcapld.NewCapability(
		&zcapld.Signer{
			SignatureSuite:     ed25519signature2018.New(suite.WithSigner(u.signer)),
			SuiteType:          ed25519signature2018.SignatureType,
			VerificationMethod: u.controller,
		},
		zcapld.WithParent(u.edvCapability.ID),
		zcapld.WithInvoker(u.response.headers[edvDIDKeyHeader]),
		zcapld.WithAllowedActions("read", "write"),
		zcapld.WithInvocationTarget(u.vaultID, edvResource),
		zcapld.WithCapabilityChain(u.edvCapability.Parent, u.edvCapability.ID))
}
