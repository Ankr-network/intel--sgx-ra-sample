
/* Standard C++ includes */
#include <stdlib.h>
#include <iostream>
#include <string>

int sgx_boinc_sp_call_remote_attestation(char* spid, char* signing_cafile,  char* ias_cert, char *ias_cert_key, char* b64quote, char verbose_flag );
