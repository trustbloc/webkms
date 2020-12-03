/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

\! echo "Configuring MySQL users...";

/*
hub auth
*/
CREATE USER 'hubauth'@'%' IDENTIFIED BY 'hubauth-secret-pw';
GRANT ALL PRIVILEGES ON `hubauth\_%` . * TO 'hubauth'@'%';

/*
hydra
*/
CREATE USER 'hydra'@'%' IDENTIFIED BY 'hydra-secret-pw';
CREATE DATABASE hydra;
GRANT ALL PRIVILEGES ON hydra.* TO 'hydra'@'%';

/*
oidc provider (hydra)
*/
CREATE USER 'thirdpartyoidc'@'%' IDENTIFIED BY 'thirdpartyoidc-secret-pw';
CREATE DATABASE thirdpartyoidc;
GRANT ALL PRIVILEGES ON thirdpartyoidc.* TO 'thirdpartyoidc'@'%';
