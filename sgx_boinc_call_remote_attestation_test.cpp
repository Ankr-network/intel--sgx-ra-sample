
#include "sgx_boinc_sp.h"

using namespace std;

int main(int argc, char *argv[])
{
    cout << "Running Test select * from sgx_report "<<endl;
    if(sgx_boinc_sp_call_remote_attestation(argc, argv) == 0){
         cout << "Running sgx remote test OK "<<endl;
    }else{
          cout << "Running sgx remote test fail "<<endl;
    }


}
