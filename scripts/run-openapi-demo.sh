#!/bin/bash
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#
set -e

DEMO_COMPOSE_OP="${DEMO_COMPOSE_OP:-up --force-recreate -d}"
COMPOSE_FILES="${DEMO_COMPOSE_FILES}"
DEMO_PATH="$PWD/${DEMO_COMPOSE_PATH}"

set -o allexport
[[ -f $DEMO_PATH/.env ]] && source $DEMO_PATH/.env
set +o allexport

cd $DEMO_PATH
docker-compose -f docker-compose.yml ${DEMO_COMPOSE_OP}
