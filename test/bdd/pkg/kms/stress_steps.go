/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package kms

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"strconv"
	"time"

	"github.com/trustbloc/kms/test/bdd/pkg/internal/bddutil"
)

const userNameTplt = "User%d"

func (s *Steps) storeSecretInHubAuthForMultipleUsers(usersNumberEnv string) error {
	usersNumber, err := getUsersNumber(usersNumberEnv)
	if err != nil {
		return err
	}

	for i := 0; i < usersNumber; i++ {
		err = s.storeSecretInHubAuth(fmt.Sprintf(userNameTplt, i))
		if err != nil {
			return err
		}
	}

	return nil
}

func (s *Steps) createEDVDataVaultForMultipleUsers(usersNumberEnv string) error {
	usersNumber, err := getUsersNumber(usersNumberEnv)
	if err != nil {
		return err
	}

	for i := 0; i < usersNumber; i++ {
		err = s.createEDVDataVault(fmt.Sprintf(userNameTplt, i))
		if err != nil {
			return err
		}
	}

	return nil
}

func (s *Steps) stressTestForMultipleUsers(usersNumberEnv, storeType, keyType, singVerifyTimesEnv, concurrencyEnv string) error {
	usersNumber, err := getUsersNumber(usersNumberEnv)
	if err != nil {
		return err
	}

	singVerifyTimes, err  := getRepeatTimes(singVerifyTimesEnv)
	if err != nil {
		return err
	}

	concurrencyReq, err := getConcurrencyReq(concurrencyEnv, err)
	if err != nil {
		return err
	}

	if storeType != "EDV" && storeType != "LocalStorage" {
		return errors.New("invalid store type:" + storeType)
	}

	var edvCapabilities [][]byte

	for i := 0; i < usersNumber; i++ {
		userName := fmt.Sprintf(userNameTplt, i)

		u := s.users[userName]
		if err := s.createDID(u); err != nil {
			return err
		}
	}

	if storeType == "EDV" {
		edvCapabilities = make([][]byte, 0)

		for i := 0; i < usersNumber; i++ {
			userName := fmt.Sprintf(userNameTplt, i)

			u := s.users[userName]

			edvCapability, err := s.createChainCapability(u)
			if err != nil {
				return err
			}

			capabilityBytes, err := json.Marshal(edvCapability)
			if err != nil {
				return err
			}

			edvCapabilities = append(edvCapabilities, capabilityBytes)
		}
	}

	createPool := bddutil.NewWorkerPool(concurrencyReq, s.logger)

	createPool.Start()

	createStart := time.Now()

	for i := 0; i < usersNumber; i++ {
		r := &createKeyStoreRequest{
			userName:     fmt.Sprintf(userNameTplt, i),
			keyServerURL: s.bddContext.KeyServerURL,
			edvServerURL: s.bddContext.EDVServerURL,
			steps:        s,
		}
		if edvCapabilities != nil {
			r.edvCapability = edvCapabilities[i]
		}
		createPool.Submit(r)
	}

	createPool.Stop()

	createTimeStr := time.Since(createStart).String()

	s.logger.Infof("got created key store %d responses for %d requests", len(createPool.Responses()), usersNumber)

	if len(createPool.Responses()) != usersNumber {
		return fmt.Errorf("expecting created key store %d responses but got %d", usersNumber, len(createPool.Responses()))
	}

	for _, resp := range createPool.Responses() {
		if resp.Err != nil {
			return resp.Err
		}
	}

	createKeyPool := bddutil.NewWorkerPool(concurrencyReq, s.logger)

	createKeyPool.Start()

	createKeyStart := time.Now()

	for i := 0; i < usersNumber; i++ {
		createKeyPool.Submit(&createKeyRequest{
			userName:     fmt.Sprintf(userNameTplt, i),
			keyServerURL: s.bddContext.KeyServerURL,
			keyType:      keyType,
			steps:        s,
		})
	}

	createKeyPool.Stop()

	s.logger.Infof("got created key %d responses for %d requests", len(createKeyPool.Responses()), usersNumber)

	if len(createKeyPool.Responses()) != usersNumber {
		return fmt.Errorf("expecting created key %d responses but got %d", usersNumber, len(createKeyPool.Responses()))
	}

	createKeyTimeStr := time.Since(createKeyStart).String()

	for _, resp := range createKeyPool.Responses() {
		if resp.Err != nil {
			return resp.Err
		}
	}

	signVerifyPool := bddutil.NewWorkerPool(concurrencyReq, s.logger)

	signVerifyPool.Start()

	signVerifyStart := time.Now()

	for i := 0; i < usersNumber; i++ {
		signVerifyPool.Submit(&signVerifyRequest{
			userName:     fmt.Sprintf(userNameTplt, i),
			keyServerURL: s.bddContext.KeyServerURL,
			times:        singVerifyTimes,
			steps:        s,
		})
	}

	signVerifyPool.Stop()

	s.logger.Infof("got sign verify %d responses for %d requests", len(signVerifyPool.Responses()), usersNumber)

	if len(signVerifyPool.Responses()) != usersNumber {
		return fmt.Errorf("expecting sign verify %d responses but got %d", usersNumber, len(signVerifyPool.Responses()))
	}

	signVerifyTimeStr := time.Since(signVerifyStart).String()

	for _, resp := range signVerifyPool.Responses() {
		if resp.Err != nil {
			return resp.Err
		}
	}

	fmt.Printf("   Created key store %d took: %s\n", usersNumber, createTimeStr)
	fmt.Printf("   Created key %d took: %s\n", usersNumber, createKeyTimeStr)
	fmt.Printf("   Sign and verify %d took: %s\n", usersNumber*singVerifyTimes, signVerifyTimeStr)

	return nil
}

func getConcurrencyReq(concurrencyEnv string, err error) (int, error) {
	concurrencyReqStr := os.Getenv(concurrencyEnv)
	if concurrencyReqStr == "" {
		concurrencyReqStr = "10"
	}

	return strconv.Atoi(concurrencyReqStr)
}

func getUsersNumber(usersNumberEnv string) (int, error) {
	usersNumberStr := os.Getenv(usersNumberEnv)
	if usersNumberStr == "" {
		usersNumberStr = "10"
	}

	return strconv.Atoi(usersNumberStr)
}

func getRepeatTimes(repeatTimesEnv string) (int, error) {
	repeatTimesStr := os.Getenv(repeatTimesEnv)
	if repeatTimesStr == "" {
		repeatTimesStr = "5"
	}

	return strconv.Atoi(repeatTimesStr)
}

type createKeyStoreRequest struct {
	userName      string
	edvCapability []byte
	edvServerURL  string
	keyServerURL  string
	steps         *Steps
}

func (r *createKeyStoreRequest) Invoke() (interface{}, error) {
	u := r.steps.users[r.userName]

	createReq := &createKeystoreReq{
		Controller: u.controller,
	}

	if r.edvCapability != nil {
		createReq.EDV = &edvOptions{
			VaultURL:   r.edvServerURL + edvBasePath + "/" + u.vaultID,
			Capability: r.edvCapability,
		}
	}

	return nil, r.steps.createKeystoreReq(u, createReq, r.keyServerURL+createKeystoreEndpoint)
}

type createKeyRequest struct {
	userName     string
	keyServerURL string
	keyType      string
	steps        *Steps
}

func (r *createKeyRequest) Invoke() (interface{}, error) {
	return nil, r.steps.makeCreateKeyReq(r.userName, r.keyServerURL+keysEndpoint, r.keyType)
}

type signVerifyRequest struct {
	userName     string
	keyServerURL string
	times        int
	steps        *Steps
}

func (r *signVerifyRequest) Invoke() (interface{}, error) {
	message := randomMessage(1024)
	for i := 0; i < r.times; i++ {
		err := r.steps.makeSignMessageReq(r.userName, r.keyServerURL+signEndpoint, message)
		if err != nil {
			return nil, err
		}

		err = r.steps.makeVerifySignatureReq(r.userName, r.keyServerURL+verifyEndpoint, "signature", message)
		if err != nil {
			return nil, err
		}
	}
	return nil, nil
}

var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

func randomMessage(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}
