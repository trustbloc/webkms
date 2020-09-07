# Run via CLI

The kms-rest server can be built from within the `cmd/kms-rest` directory with `go build`.

## Run the server

Start the server with `./kms-rest start [flags]`.

## Parameters

Parameters can be set by command line arguments or environment variables:

```
-u, --host-url string                     URL to run the kms-rest instance on. Format: HostName:Port.
    --tls-serve-cert string               Path to the server certificate to use when serving HTTPS. Alternatively, this can be set with the following environment variable: KMS_REST_TLS_SERVE_CERT
    --tls-serve-key string                Path to the private key to use when serving HTTPS. Alternatively, this can be set with the following environment variable: KMS_REST_TLS_SERVE_KEY

-t, --database-type string                The type of database to use for storing metadata about keystores andassociated keys. Supported options: mem, couchdb. Alternatively, this can be set with the following environment variable: DATABASE_TYPE
-v, --database-url string                 The URL of the database. Not needed if using in-memory storage. For CouchDB, include the username:password@ text if required. Alternatively, this can be set with the following environment variable: DATABASE_URL
    --database-prefix string              An optional prefix to be used when creating and retrieving underlying databases. Alternatively, this can be set with the following environment variable: DATABASE_PREFIX

-k, --kms-secrets-database-type string    The type of database to use for storing KMS secrets. Supported options: mem, couchdb. Alternatively, this can be set with the following environment variable: KMS_SECRETS_DATABASE_TYPE
-s, --kms-secrets-database-url string     The URL of the database for KMS secrets. Not needed if using in-memory storage. For CouchDB, include the username:password@ text if required. Alternatively, this can be set with the following environment variable: KMS_SECRETS_DATABASE_URL
    --kms-secrets-database-prefix string  An optional prefix to be used when creating and retrieving the underlying KMS secrets database. Alternatively, this can be set with the following environment variable: KMS_SECRETS_DATABASE_PREFIX

-l, --log-level string                    Logging level to set. Supported options: critical, error, warning, info, debug. Defaults to "info". Alternatively, this can be set with the following environment variable: KMS_REST_LOG_LEVEL
```

## Example

```sh
$ cd cmd/kms-rest
$ go build
$ ./kms-rest start --host-url localhost:8076 --database-type couchdb --database-url localhost:5984 --database-prefix keystore \
--kms-secrets-database-type couchdb --kms-secrets-database-url localhost:5984 --kms-secrets-database-prefix kms
```
