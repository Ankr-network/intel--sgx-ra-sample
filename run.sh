#g++ -std=c++11  -g  -L/opt/intel/sgxsdk/lib64 -L/opt/openssl/1.1.0i/lib   -o zys zys.cpp  agent_wget.o iasrequest.o byteorder.o common.o crypto.o hexutil.o fileio.o base64.o msgio.o logfile.o agent_curl.o -lcrypto -lcurl  -I/opt/intel/sgxsdk/include
g++ -std=c++11  -g  -L/opt/intel/sgxsdk/lib64 -L/opt/openssl/1.1.0i/lib   -o zys sgx_boinc_call_remote_attestation_test.cpp sgx_boinc_sp.cpp agent_wget.o iasrequest.o byteorder.o common.o crypto.o hexutil.o fileio.o base64.o msgio.o logfile.o agent_curl.o -lcrypto -lcurl  -I/opt/intel/sgxsdk/include
./zys
