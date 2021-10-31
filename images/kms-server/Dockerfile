#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

ARG GO_VER
ARG ALPINE_VER

FROM golang:${GO_VER}-alpine${ALPINE_VER} as builder

RUN apk update && apk add git && apk add ca-certificates
RUN adduser -D -g '' appuser
COPY . $GOPATH/src/github.com/trustbloc/kms/
WORKDIR $GOPATH/src/github.com/trustbloc/kms/

RUN cd cmd/kms-server && CGO_ENABLED=0 go build -o /usr/bin/kms-server main.go

FROM scratch

LABEL org.opencontainers.image.source https://github.com/trustbloc/kms

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /etc/passwd /etc/passwd
COPY --from=builder /usr/bin/kms-server /usr/bin/kms-server
USER appuser

ENTRYPOINT ["/usr/bin/kms-server"]
