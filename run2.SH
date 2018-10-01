g++ -DHAVE_CONFIG_H -I.  -I/opt/intel/sgxsdk/include -fno-builtin-memset -I/opt/openssl/1.1.0i/include   -std=c++11  -g -O2 -MT sp.o -MD -MP -MF .deps/sp.Tpo -c -o  sgx_boinc_sp.o sgx_boinc_sp.cpp 
ar srv sgx_boinc_sp.a sgx_boinc_sp.o agent_wget.o iasrequest.o byteorder.o common.o crypto.o hexutil.o fileio.o base64.o msgio.o logfile.o agent_curl.o

g++ -std=c++11  -g  -L/opt/intel/sgxsdk/lib64 -L/opt/openssl/1.1.0i/lib -o test sgx_boinc_call_remote_attestation_test.cpp   sgx_boinc_sp.a -lcrypto -lcurl  -I/opt/intel/sgxsdk/include

./test
