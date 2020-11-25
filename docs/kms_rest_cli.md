# Run via CLI

The kms-rest server can be built from within the `cmd/kms-rest` directory with `go build`.

## Run the server

Start the server with `./kms-rest start [flags]`.

## Parameters

Parameters can be set by command line arguments or environment variables:

```
    --host-url string                         URL to run the KMS instance on. Format: HostName:Port.

-l, --log-level string                        Logging level to set. Supported options: critical, error, warning, info, debug. Defaults to "info". Alternatively, this can be set with the following environment variable: KMS_LOG_LEVEL

-c, --tls-cacerts stringArray                 Comma-separated list of CA certs path. Alternatively, this can be set with the following environment variable: KMS_TLS_CACERTS
-s, --tls-systemcertpool string               Use system certificate pool. Possible values [true] [false]. Defaults to false if not set. Alternatively, this can be set with the following environment variable: KMS_TLS_SYSTEMCERTPOOL

    --tls-serve-cert string                   Path to the server certificate to use when serving HTTPS. Alternatively, this can be set with the following environment variable: KMS_TLS_SERVE_CERT
    --tls-serve-key string                    Path to the private key to use when serving HTTPS. Alternatively, this can be set with the following environment variable: KMS_TLS_SERVE_KEY

    --kms-master-key-path string              The path to the file with master key to be used for secret lock. If missing noop service lock is used. Alternatively, this can be set with the following environment variable: KMS_MASTER_KEY_PATH

    --database-type string                    The type of database to use for storing metadata about keystores and associated keys. Supported options: mem, couchdb. Alternatively, this can be set with the following environment variable: KMS_DATABASE_TYPE
    --database-url string                     The URL of the database. Not needed if using in-memory storage. For CouchDB, include the username:password@ text if required. Alternatively, this can be set with the following environment variable: KMS_DATABASE_URL
    --database-prefix string                  An optional prefix to be used when creating and retrieving underlying databases. Alternatively, this can be set with the following environment variable: KMS_DATABASE_PREFIX

    --kms-secrets-database-type string        The type of database to use for storing KMS secrets for Keystore. Supported options: mem, couchdb. Alternatively, this can be set with the following environment variable: KMS_SECRETS_DATABASE_TYPE
    --kms-secrets-database-url string         The URL of the database for KMS secrets. Not needed if using in-memory storage. For CouchDB, include the username:password@ text if required. Alternatively, this can be set with the following environment variable: KMS_SECRETS_DATABASE_URL
    --kms-secrets-database-prefix string      An optional prefix to be used when creating and retrieving the underlying KMS secrets database. Alternatively, this can be set with the following environment variable: KMS_SECRETS_DATABASE_PREFIX

    --key-manager-storage-type string         The type of storage to use for user's key manager. Supported options: mem, couchdb, edv. Alternatively, this can be set with the following environment variable: KMS_KEY_MANAGER_STORAGE_TYPE
    --key-manager-storage-url string          The URL of storage for user's key manager. Not needed if using in-memory storage. For CouchDB, include the username:password@ text if required. Alternatively, this can be set with the following environment variable: KMS_KEY_MANAGER_STORAGE_URL
    --key-manager-storage-prefix string       An optional prefix to be used when creating and retrieving the underlying user's key manager storage. Alternatively, this can be set with the following environment variable: KMS_KEY_MANAGER_STORAGE_PREFIX

    --hub-auth-url string                     The URL of Hub Auth server to use for fetching secret share for secret lock. If not specified secret lock based on master key is used. Alternatively, this can be set with the following environment variable: KMS_HUB_AUTH_URL
```

## Example

```sh
$ cd cmd/kms-rest
$ go build
$ ./kms-rest start --host-url localhost:8076 --database-type couchdb --database-url admin:password@couchdb.example.com:5984 --database-prefix keystore \
--kms-secrets-database-type couchdb --kms-secrets-database-url admin:password@couchdb.example.com:5984 --kms-secrets-database-prefix kms \
--key-manager-storage-type couchdb --key-manager-storage-url admin:password@couchdb.example.com:5984 --key-manager-storage-prefix kms_user
```
