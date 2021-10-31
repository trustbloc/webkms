/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"os"

	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	tlsutil "github.com/trustbloc/edge-core/pkg/utils/tls"
)

var logger = log.New("mock-login-consent")

type config struct {
	listenAddr    string
	hydraAdminURL *url.URL
	tlsConfig     *tls.Config
	serveCertFile string
	serveKeyFile  string
	store         storage.Store
}

func main() {
	conf, err := loadConfig()
	if err != nil {
		logger.Errorf("failed to load config: %s", err.Error())
		os.Exit(1)
	}

	logger.Infof("initializing server on %s", conf.listenAddr)

	err = http.ListenAndServeTLS(
		conf.listenAddr,
		conf.serveCertFile,
		conf.serveKeyFile,
		newServer(conf),
	)
	if err != nil {
		logger.Errorf("server encountered an error: %s", err.Error())
		os.Exit(1)
	}
}

func loadConfig() (*config, error) {
	hydraAdminURL, err := url.Parse(os.Getenv("HYDRA_ADMIN_URL"))
	if err != nil {
		return nil, fmt.Errorf("env variable HYDRA_ADMIN_URL missing or malformed: %w", err)
	}

	serveCertPath := os.Getenv("TLS_CERT_PATH")
	if serveCertPath == "" {
		return nil, fmt.Errorf("env variable TLS_CERT_PATH required")
	}

	serveKeyPath := os.Getenv("TLS_KEY_PATH")
	if serveKeyPath == "" {
		return nil, fmt.Errorf("env variable TLS_KEY_PATH required")
	}

	rootCaCertsPath := os.Getenv("ROOT_CA_CERTS_PATH")
	if rootCaCertsPath == "" {
		return nil, fmt.Errorf("env variable ROOT_CA_CERTS_PATH required")
	}

	rootCACerts, err := tlsutil.GetCertPool(false, []string{rootCaCertsPath})
	if err != nil {
		return nil, fmt.Errorf("failed to init tls cert pool from path %s: %w", rootCaCertsPath, err)
	}

	listenAddr := os.Getenv("LISTEN_ADDR")
	if listenAddr == "" {
		return nil, fmt.Errorf("env variable LISTEN_ADDR required")
	}

	prov := mem.NewProvider()

	store, err := prov.OpenStore("bdd_tests")
	if err != nil {
		return nil, fmt.Errorf("couldn't init memory store for some reason: %w", err)
	}

	return &config{
		listenAddr:    listenAddr,
		hydraAdminURL: hydraAdminURL,
		serveCertFile: serveCertPath,
		serveKeyFile:  serveKeyPath,
		tlsConfig: &tls.Config{
			RootCAs:    rootCACerts,
			MinVersion: tls.VersionTLS13,
		},
		store: store,
	}, nil
}
