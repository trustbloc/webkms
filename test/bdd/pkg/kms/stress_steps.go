/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package kms

import (
	"fmt"
	"github.com/trustbloc/kms/test/bdd/pkg/internal/bddutil"
	"os"
	"strconv"
	"time"
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

func (s *Steps) createKeystoreForMultipleUsers(usersNumberEnv, keyType, concurrencyEnv string) error {
	usersNumber, err := getUsersNumber(usersNumberEnv)
	if err != nil {
		return err
	}

	concurrencyReq, err := getConcurrencyReq(concurrencyEnv, err)
	if err != nil {
		return err
	}

	createPool := bddutil.NewWorkerPool(concurrencyReq, s.logger)

	createPool.Start()

	createStart := time.Now()

	for i := 0; i < usersNumber; i++ {
		createPool.Submit(&createKeyRequest{
			userName: fmt.Sprintf(userNameTplt, i),
			keyType:  keyType,
			steps:    s,
		})
	}

	createPool.Stop()

	createTimeStr := time.Since(createStart).String()

	s.logger.Infof("got created %d key stores for %d requests", len(createPool.Responses()), usersNumber)

	fmt.Printf("   Created key stores %d took: %s\n", usersNumber, createTimeStr)

	return nil
}

func (s *Steps) makeSignVerifyMultipleTimeForMultipleUsers(
	usersNumberEnv, endpoint, timesEnv, concurrencyEnv string) error {
	usersNumber, err := getUsersNumber(usersNumberEnv)
	if err != nil {
		return err
	}

	concurrencyReq, err := getConcurrencyReq(concurrencyEnv, err)
	if err != nil {
		return err
	}

	times, err := getRepeatTimes(timesEnv)
	if err != nil {
		return err
	}

	createPool := bddutil.NewWorkerPool(concurrencyReq, s.logger)

	createPool.Start()

	createStart := time.Now()

	for i := 0; i < usersNumber; i++ {
		createPool.Submit(&signVerifyRequest{
			userName: fmt.Sprintf(userNameTplt, i),
			endpoint: endpoint,
			times:    times,
			steps:    s,
		})
	}

	createPool.Stop()

	createTimeStr := time.Since(createStart).String()

	s.logger.Infof("got successful %d signs and verifications for %d requested", len(createPool.Responses()), usersNumber)

	fmt.Printf("   %d sign/verify requests took: %s\n", usersNumber*times, createTimeStr)

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

type createKeyRequest struct {
	userName string
	keyType  string
	steps    *Steps
}

func (r *createKeyRequest) Invoke() (interface{}, error) {
	return nil, r.steps.createKeystoreAndKey(r.userName, r.keyType)
}

type signVerifyRequest struct {
	userName string
	endpoint string
	times    int
	steps    *Steps
}

func (r *signVerifyRequest) Invoke() (interface{}, error) {

	message := "test message"
	for i := 0; i < r.times; i++ {
		err := r.steps.makeSignMessageReq(r.userName, r.endpoint, message)
		if err != nil {
			return nil, err
		}

		err = r.steps.makeVerifySignatureReq(r.userName, r.endpoint, "signature", message)
		if err != nil {
			return nil, err
		}
	}
	return nil, nil
}
