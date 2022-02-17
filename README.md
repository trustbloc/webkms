[![Release](https://img.shields.io/github/release/trustbloc/kms.svg?style=flat-square)](https://github.com/trustbloc/kms/releases/latest)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://raw.githubusercontent.com/trustbloc/kms/main/LICENSE)
[![Godocs](https://img.shields.io/badge/godoc-reference-blue.svg)](https://godoc.org/github.com/trustbloc/kms)

[![Build Status](https://dev.azure.com/trustbloc/service/_apis/build/status/trustbloc.kms?branchName=main)](https://dev.azure.com/trustbloc/service/_build/latest?definitionId=47&branchName=main)
[![codecov](https://codecov.io/gh/trustbloc/kms/branch/main/graph/badge.svg)](https://codecov.io/gh/trustbloc/kms)
[![Go Report Card](https://goreportcard.com/badge/github.com/trustbloc/kms)](https://goreportcard.com/report/github.com/trustbloc/kms)

# KMS

TrustBloc KMS is a server implementation of [KMS](https://github.com/hyperledger/aries-framework-go/blob/main/pkg/kms/api.go)
and [Crypto](https://github.com/hyperledger/aries-framework-go/blob/main/pkg/crypto/api.go) APIs from [Aries Framework Go](https://github.com/hyperledger/aries-framework-go).
The KMS server adds a layer of security and storage options for the cryptographic keys. KMS/Crypto operations are exposed
over [REST API](#rest-api).

## Running kms-server

Run `make kms-server` to build a `kms-server` executable. You can also build a docker image using `make kms-server-docker`.

Start the KMS server with the following command:

```sh
$ ./build/bin/kms-server start [flags]
```

or

```sh
$ docker run -p 8074:8074 ghcr.io/trustbloc/kms:latest start [flags]
```

If the server is run as a docker container, you need to expose the port on which the KMS server is listening for
incoming connections.

**Example with MongoDB and local secret lock:**

```sh
$ ./build/bin/kms-server start --host localhost:8076 --database-type mongodb --database-url mongodb://mongodb.example.com:27017 --secret-lock-type=local --secret-lock-key-path=<path_to_key>
```

### Flags

| Flag                         | Environment variable           | Description                                                                                                |
|------------------------------|--------------------------------|------------------------------------------------------------------------------------------------------------|
| --host                       | KMS_HOST                       | The host to run the kms-server on. Format: HostName:Port.                                                  |
| --metrics-host               | KMS_METRICS_HOST               | The host to run metrics on. Format: HostName:Port.                                                         |
| --base-url                   | KMS_BASE_URL                   | An optional base URL value to prepend to a key store URL.                                                  |
| --database-type              | KMS_DATABASE_TYPE              | The type of database to use for storing key stores metadata. Supported options: mem, couchdb, mongodb.     |
| --database-url               | KMS_DATABASE_URL               | The URL of the database. Not needed if using in-memory storage.                                            |
| --database-prefix            | KMS_DATABASE_PREFIX            | An optional prefix to be used when creating and retrieving the underlying database.                        |
| --database-timeout           | KMS_DATABASE_TIMEOUT           | Total time to wait for the database to become available. Supports valid duration strings. Defaults to 30s. |
| --secret-lock-type           | KMS_SECRET_LOCK_TYPE           | Type of a secret lock used to protect server KMS. Supported options: local, aws.                           |
| --secret-lock-key-path       | KMS_SECRET_LOCK_KEY_PATH       | The path to the file with key to be used by local secret lock. If missing noop service lock is used.       |
| --secret-lock-aws-key-uri    | KMS_SECRET_LOCK_AWS_KEY_URI    | The URI of AWS key to be used by server secret lock if the secret lock type is "aws".                      |
| --secret-lock-aws-access-key | KMS_SECRET_LOCK_AWS_ACCESS_KEY | The AWS access key ID to be used by server secret lock if the secret lock type is "aws".                   |
| --secret-lock-aws-secret-key | KMS_SECRET_LOCK_AWS_SECRET_KEY | The AWS secret access key to be used by server secret lock if the secret lock type is "aws".               |
| --auth-server-url            | KMS_AUTH_SERVER_URL            | The URL of Auth server to use for fetching secret share for Shamir secret lock.                            |
| --auth-server-token          | KMS_AUTH_SERVER_TOKEN          | A static token used to protect the GET /secrets API in Auth server.                                        |
| --secret-lock-aws-endpoint   | KMS_SECRET_LOCK_AWS_ENDPOINT   | The endpoint of AWS KMS service. Should be set only in a test environment.                                 |
| --tls-cacerts                | KMS_TLS_CACERTS                | Comma-separated list of CA certs path.                                                                     |
| --tls-serve-cert             | KMS_TLS_SERVE_CERT             | The path to the server certificate to use when serving HTTPS.                                              |
| --tls-serve-key              | KMS_TLS_SERVE_KEY              | The path to the private key to use when serving HTTPS.                                                     |
| --tls-systemcertpool         | KMS_TLS_SYSTEMCERTPOOL         | Use system certificate pool. Possible values: [true] [false]. Defaults to false.                           |
| --did-domain                 | KMS_DID_DOMAIN                 | The URL to the did consortium's domain.                                                                    |
| --key-store-cache-ttl        | KMS_KEY_STORE_CACHE_TTL        | An optional value for key store cache TTL (time to live). Defaults to 10m if caching is enabled.           |
| --enable-cache               | KMS_CACHE_ENABLE               | Enables caching support. Possible values: [true] [false]. Defaults to true.
| --shamir-secret-cache-ttl    | KMS_SHAMIR_SECRET_CACHE_TTL    | An optional value for Shamir secrets cache TTL. Defaults to 10m if caching is enabled. If set to 0, keys are never cached. | 
| --kms-cache-ttl              | KMS_KMS_CACHE_TTL              | An optional value for cache TTL for keys stored in server kms. Defaults to 10m if caching is enabled. If set to 0, keys are never cached. |
| --enable-cors                | KMS_CORS_ENABLE                | Enables CORS. Possible values: [true] [false]. Defaults to false.                                          |
| --enable-zcap                | KMS_ZCAP_ENABLE                | Enables ZCAPs authorization. Possible values: [true] [false]. Defaults to false.                           |
| --log-level                  | KMS_LOG_LEVEL                  | Logging level. Supported options: critical, error, warning, info, debug. Defaults to info.                 |

## Running tests

### Prerequisites

- Go 1.17
- Docker
- Docker-Compose
- Make
- `127.0.0.1 oidc.provider.example.com` entry in `hosts` file

### Targets

```sh
# run all build targets
$ make all

# run license and linter checks
$ make checks

# run unit tests
$ make unit-test

# run bdd tests
$ make bdd-test
```

## REST API

### Generate OpenAPI specification

The OpenAPI spec for the `kms-server` can be generated by running the following target from the project root directory:

```sh
$ make open-api-spec
```

The generated spec can be found under `./test/bdd/fixtures/specs/openAPI.yml`.

### Run OpenAPI demo

Start the OpenAPI demo by running

```sh
$ make open-api-demo
```

Once the services are up, click [here](http://localhost:8089/openapi/) to launch the OpenAPI interface.

## Architecture overview

![kms-server-architecture](https://user-images.githubusercontent.com/239837/147811170-11b2388b-df39-4d40-ac4a-69b1f406392c.png)

### Secret lock

Secret lock is used to encrypt keys before storing them into the underlying storage. **No key materials are ever stored unencrypted**.
Secret lock can be any component that supports [secretlock.Service API](https://github.com/hyperledger/aries-framework-go/blob/main/pkg/secretlock/api.go)
from the Aries Framework Go.

All secret locks, currently used by the KMS server, use symmetric keys. The way how these keys are built or get from
differentiates one secret lock from another.

#### Local secret lock

Local secret lock uses a key that is created and stored locally. In the case of User's Key Store, a symmetric key for
the local secret lock is created during `create key store` operation. It is encrypted by Server's Secret Lock and stored
to the Server DB.

Local secret lock for the KMS server reads the key from the file specified by `KMS_SECRET_LOCK_KEY_PATH` variable
(`--secret-lock-key-path` flag).

#### AWS secret lock

Server's Secret Lock can use a key hosted by AWS KMS. Set `KMS_SECRET_LOCK_TYPE=aws` variable (`--secret-lock-type=aws` flag)
to enable option with AWS secret lock. You will need to provide other parameters that are needed for using AWS key:
`KMS_SECRET_LOCK_AWS_KEY_URI`, `KMS_SECRET_LOCK_AWS_ACCESS_KEY` and `KMS_SECRET_LOCK_AWS_SECRET_KEY` variables or appropriate flags.

#### Shamir secret lock

That type of secret lock can be forced to use for the User's Key Store by the KMS Server. If the server is started with
`KMS_AUTH_SERVER_URL` variable set, then keys in the User's Key Store should be protected with Shamir secret lock.
This lock uses Shamir's Secret Sharing scheme to reconstruct the original secret from the provided shares and the HKDF
algorithm to expand the combined secret into a symmetric key to use for encrypt/decrypt operations.

If Shamir secret lock is used, every request that involves User's Key Store is expected to have a base64 encoded
`Secret-Share` header with user's secret share and `Auth-User` header to fetch the second share from the Auth server.

### Storage

The following databases are supported for the Server DB: MongoDB, CouchDB, and in-memory. You specify a type of the
database in the `KMS_DATABASE_TYPE` environment variable (`--database-type` flag).

User's Key Store can also use EDV for storing working keys. EDV parameters can be set with `create key store` request:

```json
{
  "controller": "did:example:controller",
  "edv": {
    "vault_url": "https://edv-host/encrypted-data-vaults/vault-id",
    "capability": "eyJAY29udGV4dCI6Imh0dHBzOi8vdzNpZC5v..."
  }
}
```

## Contributing

Thank you for your interest in contributing. Please see our [community contribution guidelines](https://github.com/trustbloc/community/blob/main/CONTRIBUTING.md)
for more information.

## License

Apache License, Version 2.0 (Apache-2.0). See the [LICENSE](LICENSE) file.
