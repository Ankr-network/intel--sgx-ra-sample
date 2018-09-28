
#include "sgx_boinc_client.h"

using namespace std;

int main(int argc, char *argv[])
{
    cout << "Running Test select * from sgx_report "<<endl;
    if(sgx_boinc_client_init(argc, argv) == 0){
         cout << "Running sgx remote test OK "<<endl;
    }else{
          cout << "Running sgx remote test fail "<<endl;
    }


}
