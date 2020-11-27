/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

\! echo "Configuring MySQL users...";

/*
auth rest
*/
CREATE USER 'authrest'@'%' IDENTIFIED BY 'authrest-secret-pw';
GRANT ALL PRIVILEGES ON `authrest\_%` . * TO 'authrest'@'%';

/*
auth rest hydra
*/
CREATE USER 'authresthydra'@'%' IDENTIFIED BY 'authresthydra-secret-pw';
CREATE DATABASE authresthydra;
GRANT ALL PRIVILEGES ON authresthydra.* TO 'authresthydra'@'%';


/*
third party oidc (hydra)
*/
CREATE USER 'thirdpartyoidc'@'%' IDENTIFIED BY 'thirdpartyoidc-secret-pw';
CREATE DATABASE thirdpartyoidc;
GRANT ALL PRIVILEGES ON thirdpartyoidc.* TO 'thirdpartyoidc'@'%';
