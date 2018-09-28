#!/usr/bin/env bash

echo "Demostrate IAS SigRL API"

# URL of IAS server in development environment
IAS_SERVER="https://test-as.sgx.trustedservices.intel.com:443"

# SPID private key
KEY="../certs/domain.key"

# SPID self-signed certificate registered on IAS
CERTIFICATE="../certs/domain.crt"

# SigRL API endpoint
SIGRL_ENDPOINT="attestation/sgx/v3/sigrl"

# Big endian-formatted group ID of SGX platform
GID="00000afb"

curl \
  -vvv \
  --key ${KEY} --cert ${CERTIFICATE} \
  ${IAS_SERVER}/${SIGRL_ENDPOINT}/${GID}
