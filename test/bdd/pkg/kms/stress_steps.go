/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package kms

import (
	"errors"
	"fmt"
	"math/rand"
	"os"
	"strconv"
	"time"

	"github.com/greenpau/go-calculator"

	"github.com/trustbloc/kms/test/bdd/pkg/internal/bddutil"
)

const (
	userNameTplt = "User%d"
	controller   = "did:example:123456789"
)

func (s *Steps) createUsers(usersNumberEnv string) error {
	usersNumber, err := getUsersNumber(usersNumberEnv)
	if err != nil {
		return err
	}

	for i := 0; i < usersNumber; i++ {
		userName := fmt.Sprintf(userNameTplt, i)

		u := &user{
			name:        userName,
			controller:  controller,
			disableZCAP: true,
		}
		s.users[userName] = u

		if err != nil {
			return err
		}
	}

	return nil
}

func (s *Steps) createProfileOnAuthServerForMultipleUsers(usersNumberEnv string) error {
	usersNumber, err := getUsersNumber(usersNumberEnv)
	if err != nil {
		return err
	}

	for i := 0; i < usersNumber; i++ {
		err = s.createProfileOnAuthServer(fmt.Sprintf(userNameTplt, i))
		if err != nil {
			return err
		}
	}

	return nil
}

//nolint:funlen,gocyclo
func (s *Steps) stressTestForMultipleUsers(
	totalRequestsEnv, storeType, keyType string, signTimes int, concurrencyEnv string) error {
	totalRequests, err := getUsersNumber(totalRequestsEnv)
	if err != nil {
		return err
	}

	concurrencyReq, err := getConcurrencyReq(concurrencyEnv)
	if err != nil {
		return err
	}

	if storeType != "LocalStorage" {
		return errors.New("invalid store type:" + storeType)
	}

	fmt.Printf("totalRequests: %d, concurrencyReq: %d", totalRequests, concurrencyReq)

	createPool := bddutil.NewWorkerPool(concurrencyReq, s.logger)

	createPool.Start()

	for i := 0; i < totalRequests; i++ {
		r := &stressRequest{
			userName:     fmt.Sprintf(userNameTplt, i),
			keyServerURL: s.bddContext.KeyServerURL,
			keyType:      keyType,
			steps:        s,
			signRequests: signTimes,
		}

		createPool.Submit(r)
	}

	createPool.Stop()

	s.logger.Infof("got created key store %d responses for %d requests", len(createPool.Responses()), totalRequests)

	if len(createPool.Responses()) != totalRequests {
		return fmt.Errorf("expecting created key store %d responses but got %d", totalRequests, len(createPool.Responses()))
	}

	var (
		createKeyStoreHTTPTime []int64
		createKeyHTTPTime      []int64
		signHTTPTime           []int64
		verifyHTTPTime         []int64
	)

	for _, resp := range createPool.Responses() {
		if resp.Err != nil {
			return resp.Err
		}

		perfInfo, ok := resp.Resp.(stressRequestPerfInfo)
		if !ok {
			return fmt.Errorf("invalid stressRequestPerfInfo response")
		}

		createKeyStoreHTTPTime = append(createKeyStoreHTTPTime, perfInfo.createKeyStoreHTTPTime)
		createKeyHTTPTime = append(createKeyHTTPTime, perfInfo.createKeyHTTPTime)
		signHTTPTime = append(signHTTPTime, perfInfo.signHTTPTime)
		verifyHTTPTime = append(verifyHTTPTime, perfInfo.verifyHTTPTime)
	}

	calc := calculator.NewInt64(createKeyStoreHTTPTime)
	fmt.Printf("create key store avg time: %s\n", (time.Duration(calc.Mean().Register.Mean) *
		time.Millisecond).String())
	fmt.Printf("create key store max time: %s\n", (time.Duration(calc.Max().Register.MaxValue) *
		time.Millisecond).String())
	fmt.Printf("create key store min time: %s\n", (time.Duration(calc.Min().Register.MinValue) *
		time.Millisecond).String())
	fmt.Println("------")

	calc = calculator.NewInt64(createKeyHTTPTime)
	fmt.Printf("create key avg time: %s\n", (time.Duration(calc.Mean().Register.Mean) *
		time.Millisecond).String())
	fmt.Printf("create key max time: %s\n", (time.Duration(calc.Max().Register.MaxValue) *
		time.Millisecond).String())
	fmt.Printf("create key min time: %s\n", (time.Duration(calc.Min().Register.MinValue) *
		time.Millisecond).String())
	fmt.Println("------")

	calc = calculator.NewInt64(signHTTPTime)
	fmt.Printf("sign avg time: %s\n", (time.Duration(calc.Mean().Register.Mean) *
		time.Millisecond).String())
	fmt.Printf("sign max time: %s\n", (time.Duration(calc.Max().Register.MaxValue) *
		time.Millisecond).String())
	fmt.Printf("sign min time: %s\n", (time.Duration(calc.Min().Register.MinValue) *
		time.Millisecond).String())
	fmt.Println("------")

	calc = calculator.NewInt64(verifyHTTPTime)
	fmt.Printf("verify avg time: %s\n", (time.Duration(calc.Mean().Register.Mean) *
		time.Millisecond).String())
	fmt.Printf("verify max time: %s\n", (time.Duration(calc.Max().Register.MaxValue) *
		time.Millisecond).String())
	fmt.Printf("verify min time: %s\n", (time.Duration(calc.Min().Register.MinValue) *
		time.Millisecond).String())
	fmt.Println("------")

	return nil
}

func getConcurrencyReq(concurrencyEnv string) (int, error) {
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

type stressRequest struct {
	userName     string
	keyServerURL string
	keyType      string
	steps        *Steps
	signRequests int
}

type stressRequestPerfInfo struct {
	createKeyStoreHTTPTime int64
	createKeyHTTPTime      int64
	signHTTPTime           int64
	verifyHTTPTime         int64
}

func (r *stressRequest) Invoke() (interface{}, error) {
	u := r.steps.users[r.userName]

	createReq := &createKeystoreReq{
		Controller: u.controller,
	}

	perfInfo := stressRequestPerfInfo{}

	startTime := time.Now()

	err := r.steps.createKeystoreReq(u, createReq, r.keyServerURL+createKeystoreEndpoint)
	if err != nil {
		return nil, fmt.Errorf("create keystore %w", err)
	}

	perfInfo.createKeyStoreHTTPTime = time.Since(startTime).Milliseconds()

	startTime = time.Now()

	err = r.steps.makeCreateKeyReq(r.userName, r.keyServerURL+keysEndpoint, r.keyType)
	if err != nil {
		return nil, fmt.Errorf("create key %w", err)
	}

	perfInfo.createKeyHTTPTime = time.Since(startTime).Milliseconds()

	message := randomMessage(1024) //nolint:gomnd

	startTime = time.Now()

	for i := 0; i < r.signRequests; i++ {
		err = r.steps.makeSignMessageReq(r.userName, r.keyServerURL+signEndpoint, message)
		if err != nil {
			return nil, fmt.Errorf("sign %w", err)
		}
	}

	perfInfo.signHTTPTime = time.Since(startTime).Milliseconds() / int64(r.signRequests)

	startTime = time.Now()

	err = r.steps.makeVerifySignatureReq(r.userName, r.keyServerURL+verifyEndpoint, "signature", message)
	if err != nil {
		return nil, err
	}

	perfInfo.verifyHTTPTime = time.Since(startTime).Milliseconds()

	return perfInfo, nil
}

var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ") //nolint:gochecknoglobals

func randomMessage(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))] //nolint:gosec
	}

	return string(b)
}
