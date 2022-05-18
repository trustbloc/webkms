#!/bin/sh
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

echo "Creating client for auth..."
# will use --skip-tls-verify because hydra doesn't trust self-signed certificate
# remove it when using real certificate
hydra clients create \
    --endpoint https://oidc.provider.example.com:5556 \
    --id auth \
    --secret auth-secret \
    --grant-types authorization_code,refresh_token \
    --response-types code,id_token \
    --scope openid,profile,email \
    --skip-tls-verify \
    --callbacks https://auth.trustbloc.local:8070/oauth2/callback

echo "Finished creating oidc client!"

echo "Creating oidc client for gnap flow..."
# will use --skip-tls-verify because hydra doesn't trust self-signed certificate
# remove it when using real certificate
hydra clients create \
    --endpoint https://oidc.provider.example.com:5556 \
    --id auth1 \
    --secret auth-secret \
    --grant-types authorization_code,refresh_token \
    --response-types code,id_token \
    --scope openid,profile,email \
    --skip-tls-verify \
    --callbacks https://auth.trustbloc.local:8070/oidc/callback

echo "Finished creating oidc client for gnap flow!"
