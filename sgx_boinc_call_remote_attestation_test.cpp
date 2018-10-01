
#include "sgx_boinc_sp.h"

using namespace std;

int main(int argc, char *argv[])
{

  char* b64quote= "AgAAAPoKAAAHAAYAAAAAADQVojnDto72bq2YsaLQHirmCGrHHUmt08LRyclZLFf4BQX///8CAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABwAAAAAAAAAHAAAAAAAAANS16kwG2tk/a775pT+YR9M1jfxd7JqjZ6CsEnnxTndXAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAC9ccY4Dvd8VBfostHOLUtlBLn0GOUEk0JEDP/yRD2VvQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABW9NIXvpRCgapTzL9gPMPLuYxzsRSEUILnCewQjBGaOQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAqAIAAJqZc9uf1h8OXxrqr5PowV75nnZwscUgFZzLf9B3mUADpGICH2nYuXk3zd2TzKoSe6/XPRoKMQJh1YZ5n4tdNLPlJeKJwNz7l4CB/xvqdFFs03lqtgdc+eHTqvBjYmPX1XPhaVoxi2U3YoAYUPVp0hP+F1/pHiG8ItXnqKbkgpgRS5nCRCFfGE8M/ASHoJaY8PyHGBj6mqbbDTkEyRpAvSDcEntBcs5wOaWt/oTeQsg5yRdBg09v9hS1TNdfQnpUnsSXt4+0yvM5IE/XjUa32JwtKZ83I+yrcjn6+uy3w0dedptkbzvKh12Vfc35WI9NwCWaV7Ja/VHt8dthMrNvKo15h3VeiQbEJNOa/dAbSeQEuzCSn7/qMiG1C99lqIUv4Aa8JfolU1oX7KlNzGgBAACEw0iICzh7ABNYNpG7vj/B8QALxS0nnjTLkCzsgy+7aqHFAoYEI7VVDZvYYd+7Mw1NO1M6U+cpyGNhLg+Oaavt+EaOxfDQXmWm2yIfXXrzUjxQSCzVZ9AZaB0pe/oOjqFanUe8trVvTaHMm4krOduA18auzBZ3nk6CadyOgiouevBajfNkJaoafmbPTSuz+hFwpdyrYbANl9+QoR6WRKS/XFVUsYzi5th0z/Iy7FkQu7dmZKO1e4KXvdJn0C9FWtWNFrQdZf4qHChFZbXL8dCHBktIMQGyhycyg+qUm0O6XcsLZAhr5Hnxfj435DVBIoBFFQfkwOaUwZ24//qXqks+XWORKah34NR21aIBJsWyyFLixPR/sP1nAaxWnrdG50ycvK9mV4iYwB/Ay+H/nRfMKJN559FWT+pVLFXioMiqsl3KA1hE83dNQAENIFzX2y2sjt97vCVhZaDXumpVBKL9NXBm0IROwS7dbGr7afBgX09dfCuy7+Sm";

    cout << "Running Test select * from sgx_report "<<endl;
    if(sgx_boinc_sp_call_remote_attestation("3415A239C3B68EF66EAD98B1A2D01E2A", "./certs/AttestationReportSigningCACert.pem","./certs/client.crt", "./certs/client.key", b64quote, 0) == 0){
         cout << "Running sgx remote test OK "<<endl;
    }else{
          cout << "Running sgx remote test fail "<<endl;
    }

    if(sgx_boinc_sp_call_remote_attestation("3415A239C3B68EF66EAD98B1A2D01E2A", "./certs/AttestationReportSigningCACert.pem","./certs/client.crt", "./certs/client.key", b64quote, 0) == 0){
         cout << "Running sgx remote test OK "<<endl;
    }else{
          cout << "Running sgx remote test fail "<<endl;
    }

    if(sgx_boinc_sp_call_remote_attestation("3415A239C3B68EF66EAD98B1A2D01E2A", "./certs/AttestationReportSigningCACert.pem","./certs/client.crt", "./certs/client.key", b64quote, 0) == 0){
         cout << "Running sgx remote test OK "<<endl;
    }else{
          cout << "Running sgx remote test fail "<<endl;
    }

    if(sgx_boinc_sp_call_remote_attestation("3415A239C3B68EF66EAD98B1A2D01E2A", "./certs/AttestationReportSigningCACert.pem","./certs/client.crt", "./certs/client.key", b64quote, 0) == 0){
         cout << "Running sgx remote test OK "<<endl;
    }else{
          cout << "Running sgx remote test fail "<<endl;
    }


}
