# Run as a Docker container

## Build the image

Build the docker image for `kms` by running the following `make` target from the project root directory:

```sh
$ make kms-docker
```

## Run the server

After building the docker image, start the server by running the command:

```sh
$ docker run ghcr.io/trustbloc/kms:latest start [flags]
```

Details about flags can be found [here](kms_server_cli.md#parameters).
