#!/usr/bin/env bash

echo "Demostrate IAS SigRL API"

# URL of IAS server in development environment
IAS_SERVER="https://test-as.sgx.trustedservices.intel.com:443"

# SPID private key
KEY="certs/isv.key"

# SPID self-signed certificate registered on IAS
CERTIFICATE="certs/isv.crt"

# Report API endpoint
REPORT_ENDPOINT="/attestation/sgx/v3/report"

# JSON-formatted attestation evidence file
# ATTESTATION_EVIDENCE="quotes/quote-from-enclave.json"
ATTESTATION_EVIDENCE="quotes/quote-from-isv.json"
# ATTESTATION_EVIDENCE="quotes/quote-from-enclave-by-hand.json"
# ATTESTATION_EVIDENCE="quotes/empty-quote.json"

cat ${ATTESTATION_EVIDENCE}

curl \
  -vvv \
  --key ${KEY} --cert ${CERTIFICATE} \
  --data @${ATTESTATION_EVIDENCE} \
  --header "Content-Type: application/json" \
  ${IAS_SERVER}/${REPORT_ENDPOINT}
