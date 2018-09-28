#!/usr/bin/env bash

echo "Demostrate IAS SigRL API"

# URL of IAS server in development environment
IAS_SERVER="https://test-as.sgx.trustedservices.intel.com:443"

# SPID private key
KEY="../certs/domain.key"

# SPID self-signed certificate registered on IAS
CERTIFICATE="../certs/domain.crt"

# Report API endpoint
REPORT_ENDPOINT="/attestation/sgx/v3/report"

# JSON-formatted attestation evidence file
ATTESTATION_EVIDENCE="../runtime-certs/ae.json"

cat ${ATTESTATION_EVIDENCE}

curl \
  -vvv \
  --key ${KEY} --cert ${CERTIFICATE} \
  --data @${ATTESTATION_EVIDENCE} \
  --header "Content-Type: application-json" \
  ${IAS_SERVER}/${REPORT_ENDPOINT}
