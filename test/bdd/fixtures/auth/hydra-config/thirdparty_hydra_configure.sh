#!/bin/sh
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

echo "Creating client for auth.rest.example.com..."
# will use --skip-tls-verify because hydra doesn't trust self-signed certificate
# remove it when using real certificate
hydra clients create \
    --endpoint https://third.party.oidc.provider.example.com:5556 \
    --id hub-auth \
    --secret hub-auth-secret \
    --grant-types authorization_code,refresh_token \
    --response-types code,id_token \
    --scope openid,profile,email \
    --skip-tls-verify \
    --callbacks https://localhost:8070/oauth2/callback

echo "Finished creating client!"
