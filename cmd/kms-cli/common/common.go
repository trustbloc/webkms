/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package common

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strconv"

	"github.com/spf13/cobra"
	"github.com/trustbloc/edge-core/pkg/log"
	cmdutils "github.com/trustbloc/edge-core/pkg/utils/cmd"
	tlsutils "github.com/trustbloc/edge-core/pkg/utils/tls"
)

var logger = log.New("kms-cli")

const (
	// TLSSystemCertPoolFlagName defines the flag for the system certificate pool.
	TLSSystemCertPoolFlagName = "tls-systemcertpool"
	// TLSSystemCertPoolFlagUsage defines the usage of the system certificate pool flag.
	TLSSystemCertPoolFlagUsage = "Use system certificate pool." +
		" Possible values [true] [false]. Defaults to false if not set." +
		" Alternatively, this can be set with the following environment variable: " + TLSSystemCertPoolEnvKey
	// TLSSystemCertPoolEnvKey defines the environment variable for the system certificate pool flag.
	TLSSystemCertPoolEnvKey = "KMS_CLI_TLS_SYSTEMCERTPOOL"

	// TLSCACertsFlagName defines the flag for the CA certs flag.
	TLSCACertsFlagName = "tls-cacerts"
	// TLSCACertsFlagUsage defines the usage of the CA certs flag.
	TLSCACertsFlagUsage = "Comma-separated list of ca certs path." +
		" Alternatively, this can be set with the following environment variable: " + TLSCACertsEnvKey
	// TLSCACertsEnvKey defines the environment variable for the CA certs flag.
	TLSCACertsEnvKey = "KMS_CLI_TLS_CACERTS"

	// AuthTokenFlagName defines the flag for the authorization bearer token.
	AuthTokenFlagName = "auth-token"
	// AuthTokenFlagUsage defines the usage of the authorization bearer token flag.
	AuthTokenFlagUsage = "Auth token." +
		" Alternatively, this can be set with the following environment variable: " + AuthTokenEnvKey
	// AuthTokenEnvKey defines the environment variable for the authorization bearer token flag.
	AuthTokenEnvKey = "KMS_CLI_AUTH_TOKEN" //nolint:gosec

	kmsURLFlagName  = "url"
	kmsURLFlagUsage = "URL to the kms server. " +
		" Alternatively, this can be set with the following environment variable: " + kmsURLEnvKey
	kmsURLEnvKey = "KMS_CLI_URL"
)

const (
	baseV1Path   = "/v1"
	keyStorePath = baseV1Path + "/keystores"
	keyVarName   = "keys"
)

// SendRequest send http request.
func SendRequest(httpClient *http.Client, req []byte, headers map[string]string, method,
	endpointURL string) ([]byte, error) {
	var httpReq *http.Request

	var err error

	if len(req) == 0 {
		httpReq, err = http.NewRequestWithContext(context.Background(),
			method, endpointURL, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create http request: %w", err)
		}
	} else {
		httpReq, err = http.NewRequestWithContext(context.Background(),
			method, endpointURL, bytes.NewBuffer(req))
		if err != nil {
			return nil, fmt.Errorf("failed to create http request: %w", err)
		}
	}

	for k, v := range headers {
		httpReq.Header.Add(k, v)
	}

	resp, err := httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}

	defer closeResponseBody(resp.Body)

	responseBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response : %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("got unexpected response from %s status '%d' body %s",
			endpointURL, resp.StatusCode, responseBytes)
	}

	return responseBytes, nil
}

func closeResponseBody(respBody io.Closer) {
	if err := respBody.Close(); err != nil {
		logger.Errorf("Failed to close response body: %v", err)
	}
}

// SendHTTPRequest send http request.
func SendHTTPRequest(httpClient *http.Client, request interface{}, headers map[string]string, method,
	endpointURL string, response interface{}) error {
	reqBytes, err := json.Marshal(request)
	if err != nil {
		return err
	}

	responseBytes, err := SendRequest(httpClient, reqBytes, headers, method, endpointURL)
	if err != nil {
		return err
	}

	return json.Unmarshal(responseBytes, response)
}

// NewHTTPClient creates new http client.
func NewHTTPClient(cmd *cobra.Command) (*http.Client, error) {
	rootCAs, err := getRootCAs(cmd)
	if err != nil {
		return nil, err
	}

	return &http.Client{
		Transport: &http.Transport{
			ForceAttemptHTTP2: true,
			TLSClientConfig: &tls.Config{
				RootCAs:    rootCAs,
				MinVersion: tls.VersionTLS12,
			},
		},
	}, nil
}

func getRootCAs(cmd *cobra.Command) (*x509.CertPool, error) {
	tlsSystemCertPoolString := cmdutils.GetUserSetOptionalVarFromString(cmd, TLSSystemCertPoolFlagName,
		TLSSystemCertPoolEnvKey)

	tlsSystemCertPool := false

	if tlsSystemCertPoolString != "" {
		var err error
		tlsSystemCertPool, err = strconv.ParseBool(tlsSystemCertPoolString)

		if err != nil {
			return nil, err
		}
	}

	tlsCACerts := cmdutils.GetUserSetOptionalVarFromArrayString(cmd, TLSCACertsFlagName,
		TLSCACertsEnvKey)

	return tlsutils.GetCertPool(tlsSystemCertPool, tlsCACerts)
}

// NewAuthTokenHeader returns auth headers.
func NewAuthTokenHeader(cmd *cobra.Command) map[string]string {
	headers := make(map[string]string)

	authToken := cmdutils.GetUserSetOptionalVarFromString(cmd, AuthTokenFlagName, AuthTokenEnvKey)
	if authToken != "" {
		headers["Authorization"] = "Bearer " + authToken
	}

	return headers
}

// GetCreateKeystorePath returns path for create keystore endpoint.
func GetCreateKeystorePath(cmd *cobra.Command) (string, error) {
	kmsURL, err := cmdutils.GetUserSetVarFromString(cmd, kmsURLFlagName,
		kmsURLEnvKey, false)
	if err != nil {
		return "", err
	}

	return kmsURL + keyStorePath, nil
}

// GetCreateKeyPath returns path for create key endpoint.
func GetCreateKeyPath(cmd *cobra.Command, keystoreID string) (string, error) {
	keystoreURL, err := GetCreateKeystorePath(cmd)
	if err != nil {
		return "", err
	}

	return keystoreURL + "/" + keystoreID + "/" + keyVarName, nil
}

// AddCommonFlags adds common flags to the given command.
func AddCommonFlags(cmd *cobra.Command) {
	cmd.Flags().StringP(TLSSystemCertPoolFlagName, "", "", TLSSystemCertPoolFlagUsage)
	cmd.Flags().StringArrayP(TLSCACertsFlagName, "", nil, TLSCACertsFlagUsage)
	cmd.Flags().StringP(AuthTokenFlagName, "", "", AuthTokenFlagUsage)
	cmd.Flags().StringP(kmsURLFlagName, "", "", kmsURLFlagUsage)
}
