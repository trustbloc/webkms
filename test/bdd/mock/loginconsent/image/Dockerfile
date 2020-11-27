#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

ARG GO_VER
ARG ALPINE_VER

FROM golang:${GO_VER}-alpine${ALPINE_VER} as golang
RUN apk add --no-cache \
	git \
	libtool \
	make;
ADD . /opt/workspace/mock-login-consent
WORKDIR /opt/workspace/mock-login-consent
ENV EXECUTABLES go git

FROM golang as golang_build
RUN go build -o mock-server .

FROM alpine:${ALPINE_VER} as base
COPY --from=golang_build /opt/workspace/mock-login-consent/mock-server /usr/local/bin/mock-server

ENTRYPOINT ["mock-server"]
