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

    --database-type string                    The type of database to use for storing metadata about keystores and associated keys. Supported options: mem, couchdb. Alternatively, this can be set with the following environment variable: KMS_DATABASE_TYPE
    --database-url string                     The URL of the database. Not needed if using in-memory storage. For CouchDB, include the username:password@ text if required. Alternatively, this can be set with the following environment variable: KMS_DATABASE_URL
    --database-prefix string                  An optional prefix to be used when creating and retrieving underlying databases. Alternatively, this can be set with the following environment variable: KMS_DATABASE_PREFIX

    --kms-secrets-database-type string        The type of database to use for storing KMS secrets for Keystore. Supported options: mem, couchdb. Alternatively, this can be set with the following environment variable: KMS_SECRETS_DATABASE_TYPE
    --kms-secrets-database-url string         The URL of the database for KMS secrets. Not needed if using in-memory storage. For CouchDB, include the username:password@ text if required. Alternatively, this can be set with the following environment variable: KMS_SECRETS_DATABASE_URL
    --kms-secrets-database-prefix string      An optional prefix to be used when creating and retrieving the underlying KMS secrets database. Alternatively, this can be set with the following environment variable: KMS_SECRETS_DATABASE_PREFIX

    --operational-kms-storage-type string     The type of storage to use for Operational (user-specific) KMS. Supported options: mem, couchdb, sds. Alternatively, this can be set with the following environment variable: KMS_OPERATIONAL_KMS_STORAGE_TYPE
    --operational-kms-storage-url string      The URL of storage for Operational KMS. Not needed if using in-memory storage. For CouchDB, include the username:password@ text if required. Alternatively, this can be set with the following environment variable: KMS_OPERATIONAL_KMS_STORAGE_URL
    --operational-kms-storage-prefix string   An optional prefix to be used when creating and retrieving the underlying Operational KMS storage. Alternatively, this can be set with the following environment variable: KMS_OPERATIONAL_KMS_STORAGE_PREFIX
```

## Example

```sh
$ cd cmd/kms-rest
$ go build
$ ./kms-rest start --host-url localhost:8076 --database-type couchdb --database-url admin:password@couchdb.example.com:5984 --database-prefix keystore \
--kms-secrets-database-type couchdb --kms-secrets-database-url admin:password@couchdb.example.com:5984 --kms-secrets-database-prefix kms \
--operational-kms-storage-type couchdb --operational-kms-storage-url admin:password@couchdb.example.com:5984 --operational-kms-storage-prefix opkms
```
