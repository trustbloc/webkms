# Run as a Docker container

## Build the image

Build the docker image for `kms-rest` by running the following make target from the project root directory:

```sh
$ make kms-rest-docker
```

## Run the server

After building the docker image, start the server by running the command:

```sh
$ docker run docker.pkg.github.com/trustbloc/hub-kms/kms-rest:latest start [flags]
```

Details about flags can be found [here](kms_rest_cli.md#parameters).
