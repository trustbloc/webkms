# Build

## Prerequisites (for running tests)

- Go 1.16
- Docker
- Docker-Compose
- Make
- `127.0.0.1 oidc.provider.example.com` entry in `hosts` file

## Targets

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
