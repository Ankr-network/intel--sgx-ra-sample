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
