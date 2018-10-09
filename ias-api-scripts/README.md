# Demo IAS API for Intel SGX

This directory features two Bash shell scripts that demonstrate the usage of the IAS API to:
* retrieve the signature revocation list; and
* verify the attestation evidence.

## Prerequisites

* Paste the ISV certificate file (`isv.crt`) used to register on IAS into the `certs` directory; and
* Paste the ISV private key (`isv.key`) into the `certs` directory.

## Signature revocation list

Retrieve the signature revocation list w/:
```
$ ./get-sigrl.sh
```

## Attestation evidence verification

Verify the attestation evidence w/:
```
$ ./get-report.sh
```

## Comparison of quote data structure on IAS API and SGX documentations

This is a comparison of fields in the quote data structure as described in the IAS API (https://software.intel.com/sites/default/files/managed/7e/3b/ias-api-spec.pdf) and SGX (https://software.intel.com/en-us/sgx-sdk-dev-reference-sgx-quote-t) documentations, respectively.

| IAS name        | IAS type  | SGX type                | SGX name      |
|-----------------|-----------|-------------------------|---------------|
| VERSION         | 2         | 2 (uint16_t)            | version       |
| SIGNATURE_TYPE  | 2         | 2 (uint16_t)            | sign_type     |
| GID             | 4         | 4 (sgx_epid_group_id_t) | epid_group_id |
| ISVSVN_QE       | 2         | 2 (sgx_isv_svn_t)       | qe_svn        |
| ISVSVN_PCE      | 2         | 2 (sgx_isv_svn_t)       | pce_svn       |
| RESERVED        | 4         | 4 (uint32_t)            | xeid          |
| BASENAME        | 32        | 32 (sgx_basename_t)     | basename      |

The table does not feature the report body and the signature length and signature fields yet.

However, I did compare the two documents and verified that the same fields in the same order with the same byte size are present in both documents.
