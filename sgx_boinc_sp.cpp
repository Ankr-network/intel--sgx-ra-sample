/*

Copyright 2018 Intel Corporation

This software and the related documents are Intel copyrighted materials,
and your use of them is governed by the express license under which they
were provided to you (License). Unless the License provides otherwise,
you may not use, modify, copy, publish, distribute, disclose or transmit
this software or the related documents without Intel's prior written
permission.

This software and the related documents are provided as is, with no
express or implied warranties, other than those that are expressly stated
in the License.

*/



#ifndef _WIN32
#include "config.h"
#endif

#include <stdlib.h>
#include <limits.h>
#include <stdio.h>
#include <sys/stat.h>
#include <string.h>
#include <sys/types.h>
#ifdef _WIN32
#include <intrin.h>
#include <openssl/applink.c>
#include "win32/getopt.h"
#else
#include <getopt.h>
#include <unistd.h>
#endif
#include <sgx_key_exchange.h>
#include <sgx_report.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include "json.hpp"
#include "common.h"
#include "hexutil.h"
#include "fileio.h"
#include "crypto.h"
#include "byteorder.h"
#include "msgio.h"
#include "protocol.h"
#include "base64.h"
#include "iasrequest.h"
#include "logfile.h"
#include "settings.h"

using namespace json;
using namespace std;

#include <map>
#include <string>
#include <iostream>
#include <algorithm>

#ifdef _WIN32
#define strdup(x) _strdup(x)
#endif

static const unsigned char def_service_private_key[32] = {
	0x90, 0xe7, 0x6c, 0xbb, 0x2d, 0x52, 0xa1, 0xce,
	0x3b, 0x66, 0xde, 0x11, 0x43, 0x9c, 0x87, 0xec,
	0x1f, 0x86, 0x6a, 0x3b, 0x65, 0xb6, 0xae, 0xea,
	0xad, 0x57, 0x34, 0x53, 0xd1, 0x03, 0x8c, 0x01
};

typedef struct config_struct {
	sgx_spid_t spid;
	uint16_t quote_type;
	EVP_PKEY *service_private_key;
	char *proxy_server;
	char *ca_bundle;
	char *user_agent;
	char *cert_file;
	char *cert_key_file;
	char *cert_passwd_file;
	unsigned int proxy_port;
	unsigned char kdk[16];
	char *cert_type[4];
	X509_STORE *store;
	X509 *signing_ca;
	unsigned int apiver;
	int strict_trust;
	char *quote_file;
} config_t;

void usage();

int derive_kdk(EVP_PKEY *Gb, unsigned char kdk[16], sgx_ra_msg1_t *msg1,
	config_t *config);

int process_msg01 (MsgIO *msg, IAS_Connection *ias, sgx_ra_msg1_t *msg1,
	sgx_ra_msg2_t *msg2, char **sigrl, config_t *config,
	 unsigned char smk[16]);

int process_msg3 (MsgIO *msg, IAS_Connection *ias, sgx_ra_msg1_t *msg1,
	ra_msg4_t *msg4, config_t *config, unsigned char smk[16],
	unsigned char mk[16], unsigned char sk[16]);

int get_sigrl (IAS_Connection *ias, int version, sgx_epid_group_id_t gid,
	char **sigrl, uint32_t *msg2);

int get_attestation_report(IAS_Connection *ias, int version,
	const char *b64quote, sgx_ps_sec_prop_desc_t sec_prop, ra_msg4_t *msg4,
	int strict_trust);

int get_proxy(char **server, unsigned int *port, const char *url);

char debug = 0;
char verbose = 0;

int sgx_boinc_sp_call_remote_attestation(char* spid, char* signing_cafile,  char* ias_cert, char *ias_cert_key, char* b64quote, char verbose_flag)
{
	char flag_spid = 0;
	char flag_pubkey = 0;
	char flag_cert = 0;
	char flag_ca = 0;
	char flag_usage = 0;
	char flag_noproxy= 0;
	char flag_prod= 0;
	char flag_stdio= 0;
	char *sigrl = NULL;
	config_t config;
	int oops;
	IAS_Connection *ias= NULL;
	MsgIO *msgio;
	char *port= NULL;

	verbose = verbose_flag;

	eprintf("SPID %s\n", spid);
	eprintf("signing_cafile %s\n", signing_cafile);
	eprintf("ias_cert %s\n", ias_cert);
	eprintf("ias_cert_key %s\n", ias_cert_key);
	eprintf("verbose_flag %d\n", verbose_flag);




	/* Create a logfile to capture debug output and actual msg data */

	fplog = create_logfile("sp.log");
	fprintf(fplog, "Server log started\n");

	/* Config defaults */

	memset(&config, 0, sizeof(config));
	strncpy((char *)config.cert_type, "PEM", 3);
	config.apiver= IAS_API_DEF_VERSION;

	/* Parse our options */



	if (!cert_load_file(&config.signing_ca, signing_cafile)) {
		crypto_perror("cert_load_file");
		eprintf("%s: could not load IAS Signing Cert CA\n", optarg);
		return 1;
	}

	config.store = cert_init_ca(config.signing_ca);
	if (config.store == NULL) {
		eprintf("%s: could not initialize certificate store\n", optarg);
		return 1;
	}

	if (!from_hexstring((unsigned char *)&config.spid, (unsigned char *)spid, 16)) {
		eprintf("SPID must be 32-byte hex string\n");
		return 1;
	}


	/* Use the default CA bundle unless one is provided */

	if ( config.ca_bundle == NULL ) {
		config.ca_bundle= strdup(DEFAULT_CA_BUNDLE);
		if ( config.ca_bundle == NULL ) {
			perror("strdup");
			return 1;
		}
		if ( debug ) eprintf("+++ Using default CA bundle %s\n",
			config.ca_bundle);
	}

	/*
	 * Use the hardcoded default key unless one is provided on the
	 * command line. Most real-world services would hardcode the
	 * key since the public half is also hardcoded into the enclave.
	 */

	if (config.service_private_key == NULL) {
		if (debug) {
			eprintf("Using default private key\n");
		}
		config.service_private_key = key_private_from_bytes(def_service_private_key);
		if (config.service_private_key == NULL) {
			crypto_perror("key_private_from_bytes");
			return 1;
		}

	}


	/* Initialize out support libraries */

	crypto_init();

	/* Initialize our IAS request object */

	try {
		ias = new IAS_Connection(
			(flag_prod) ? IAS_SERVER_PRODUCTION : IAS_SERVER_DEVELOPMENT,
			0
		);
	}
	catch (...) {
		oops = 1;
		eprintf("exception while creating IAS request object\n");
		return 1;
	}

	  ias->client_cert(ias_cert, (char *)config.cert_type);
		// We have a key file but no password.
		ias->client_key(ias_cert_key, NULL);



	/*
	 * Set the cert store for this connection. This is used for verifying
	 * the IAS signing certificate, not the TLS connection with IAS (the
	 * latter is handled using config.ca_bundle).
	 */
	ias->cert_store(config.store);

	/*
	 * Set the CA bundle for verifying the IAS server certificate used
	 * for the TLS session. If this isn't set, then the user agent
	 * will fall back to it's default.
	 */
	if ( strlen(config.ca_bundle) ) ias->ca_bundle(config.ca_bundle);





	  ra_msg4_t msg4;
	  sgx_ra_msg3_t msg3;
		if ( get_attestation_report(ias, config.apiver, b64quote,
			msg3.ps_sec_prop, &msg4, config.strict_trust) ) {

			printf("great you passed \n");
			crypto_destroy();

		}else{
      printf("you are failed\n");
		  crypto_destroy();


		}
		//
		// if ( get_attestation_report(ias, config.apiver, b64quote,
		// 	msg3.ps_sec_prop, &msg4, config.strict_trust) ) {
		//
		// 	printf("great you passed \n");
		// 	crypto_destroy();
		//
		// }else{
		// 	//printf("you are failed\n");
		//  // crypto_destroy();
		//
		//
		// }
		//
		// if ( get_attestation_report(ias, config.apiver, b64quote,
		// 	msg3.ps_sec_prop, &msg4, config.strict_trust) ) {
		//
		// 	printf("great you passed \n");
		// 	crypto_destroy();
		//
		// }else{
		// 	//printf("you are failed\n");
		//  // crypto_destroy();
		//
		//
		// }

	return 0;
}




int get_attestation_report(IAS_Connection *ias, int version,
	const char *b64quote, sgx_ps_sec_prop_desc_t secprop, ra_msg4_t *msg4,
	int strict_trust)
{
	IAS_Request *req = NULL;
	map<string,string> payload;
	vector<string> messages;
	ias_error_t status;
	string content;

	try {
		req= new IAS_Request(ias, (uint16_t) version);
	}
	catch (...) {
		eprintf("Exception while creating IAS request object\n");
		return 0;
	}

	payload.insert(make_pair("isvEnclaveQuote", b64quote));

	status= req->report(payload, content, messages);
	if ( status == IAS_OK ) {
		JSON reportObj = JSON::Load(content);

		if ( verbose ) {
			edividerWithText("Report Body");
			eprintf("%s\n", content.c_str());
			edivider();
			if ( messages.size() ) {
				edividerWithText("IAS Advisories");
				for (vector<string>::const_iterator i = messages.begin();
					i != messages.end(); ++i ) {

					eprintf("%s\n", i->c_str());
				}
				edivider();
			}
		}

		if ( verbose ) {
			edividerWithText("IAS Report - JSON - Required Fields");
			eprintf("id:\t\t\t%s\n", reportObj["id"].ToString().c_str());
			eprintf("timestamp:\t\t%s\n",
				reportObj["timestamp"].ToString().c_str());
			eprintf("isvEnclaveQuoteStatus:\t%s\n",
				reportObj["isvEnclaveQuoteStatus"].ToString().c_str());
			eprintf("isvEnclaveQuoteBody:\t%s\n",
				reportObj["isvEnclaveQuoteBody"].ToString().c_str());

			edividerWithText("IAS Report - JSON - Optional Fields");

			eprintf("platformInfoBlob:\t%s\n",
				reportObj["platformInfoBlob"].ToString().c_str());
			eprintf("revocationReason:\t%s\n",
				reportObj["revocationReason"].ToString().c_str());
			eprintf("pseManifestStatus:\t%s\n",
				reportObj["pseManifestStatus"].ToString().c_str());
			eprintf("pseManifestHash:\t%s\n",
				reportObj["pseManifestHash"].ToString().c_str());
			eprintf("nonce:\t%s\n", reportObj["nonce"].ToString().c_str());
			eprintf("epidPseudonym:\t%s\n",
				reportObj["epidPseudonym"].ToString().c_str());
			edivider();
		}

		/*
		 * This sample's attestion policy is based on isvEnclaveQuoteStatus:
		 *
		 *   1) if "OK" then return "Trusted"
		 *
		 *   2) if "CONFIGURATION_NEEDED" then return
		 *       "NotTrusted_ItsComplicated" when in --strict-trust-mode
		 *        and "Trusted_ItsComplicated" otherwise
		 *
		 *   3) return "NotTrusted" for all other responses
		 *
		 *
		 * ItsComplicated means the client is not trusted, but can
		 * conceivable take action that will allow it to be trusted
		 * (such as a BIOS update).
		 */

		/*
		 * Simply check to see if status is OK, else enclave considered
		 * not trusted
		 */

		memset(msg4, 0, sizeof(ra_msg4_t));

			if ( verbose ) edividerWithText("ISV Enclave Trust Status");

		if ( !(reportObj["isvEnclaveQuoteStatus"].ToString().compare("OK"))) {
			msg4->status = Trusted;
			if ( verbose ) eprintf("Enclave TRUSTED\n");
		} else if ( !(reportObj["isvEnclaveQuoteStatus"].ToString().compare("CONFIGURATION_NEEDED"))) {
			if ( strict_trust ) {
				msg4->status = NotTrusted_ItsComplicated;
				if ( verbose ) eprintf("Enclave NOT TRUSTED and COMPLICATED - Reason: %s\n",
					reportObj["isvEnclaveQuoteStatus"].ToString().c_str());
			} else {
				// Trust the enclave even if it's complicated
				if ( verbose ) eprintf("Enclave TRUSTED and COMPLICATED - Reason: %s\n",
					reportObj["isvEnclaveQuoteStatus"].ToString().c_str());
				msg4->status = Trusted;
			}
		} else if ( !(reportObj["isvEnclaveQuoteStatus"].ToString().compare("GROUP_OUT_OF_DATE"))) {
			msg4->status = NotTrusted_ItsComplicated;
			if ( verbose ) eprintf("Enclave NOT TRUSTED and COMPLICATED - Reason: %s\n",
				reportObj["isvEnclaveQuoteStatus"].ToString().c_str());
		} else {
			msg4->status = NotTrusted;
			if ( verbose ) eprintf("Enclave NOT TRUSTED - Reason: %s\n",
				reportObj["isvEnclaveQuoteStatus"].ToString().c_str());
		}


		/* Check to see if a platformInfoBlob was sent back as part of the
		 * response */

		if (!reportObj["platformInfoBlob"].IsNull()) {
			if ( verbose ) eprintf("A Platform Info Blob (PIB) was provided by the IAS\n");

			/* The platformInfoBlob has two parts, a TVL Header (4 bytes),
			 * and TLV Payload (variable) */

			string pibBuff = reportObj["platformInfoBlob"].ToString();

			/* remove the TLV Header (8 base16 chars, ie. 4 bytes) from
			 * the PIB Buff. */

			pibBuff.erase(pibBuff.begin(), pibBuff.begin() + (4*2));

			int ret = from_hexstring ((unsigned char *)&msg4->platformInfoBlob,
				pibBuff.c_str(), pibBuff.length());
		} else {
			if ( verbose ) eprintf("A Platform Info Blob (PIB) was NOT provided by the IAS\n");
		}

						return 1;
	}

	eprintf("attestation query returned %lu: \n", status);

	switch(status) {
		case IAS_QUERY_FAILED:
			eprintf("Could not query IAS\n");
			break;
		case IAS_BADREQUEST:
			eprintf("Invalid payload\n");
			break;
		case IAS_UNAUTHORIZED:
			eprintf("Failed to authenticate or authorize request\n");
			break;
		case IAS_SERVER_ERR:
			eprintf("An internal error occurred on the IAS server\n");
			break;
		case IAS_UNAVAILABLE:
			eprintf("Service is currently not able to process the request. Try again later.\n");
			break;
		case IAS_INTERNAL_ERROR:
			eprintf("An internal error occurred while processing the IAS response\n");
			break;
		case IAS_BAD_CERTIFICATE:
			eprintf("The signing certificate could not be validated\n");
			break;
		case IAS_BAD_SIGNATURE:
			eprintf("The report signature could not be validated\n");
			break;
		default:
			if ( status >= 100 && status < 600 ) {
				eprintf("Unexpected HTTP response code\n");
			} else {
				eprintf("An unknown error occurred.\n");
			}
	}

	return 0;
}

// Break a URL into server and port. NOTE: This is a simplistic algorithm.

int get_proxy(char **server, unsigned int *port, const char *url)
{
	size_t idx1, idx2;
	string lcurl, proto, srv, sport;

	if (url == NULL) return 0;

	lcurl = string(url);
	// Make lower case for sanity
	transform(lcurl.begin(), lcurl.end(), lcurl.begin(), ::tolower);

	idx1= lcurl.find_first_of(":");
	proto = lcurl.substr(0, idx1);
	if (proto == "https") *port = 443;
	else if (proto == "http") *port = 80;
	else return 0;

	idx1 = lcurl.find_first_not_of("/", idx1 + 1);
	if (idx1 == string::npos) return 0;

	idx2 = lcurl.find_first_of(":", idx1);
	if (idx2 == string::npos) {
		idx2 = lcurl.find_first_of("/", idx1);
		if (idx2 == string::npos) srv = lcurl.substr(idx1);
		else srv = lcurl.substr(idx1, idx2 - idx1);
	}
	else {
		srv= lcurl.substr(idx1, idx2 - idx1);
		idx1 = idx2+1;
		idx2 = lcurl.find_first_of("/", idx1);

		if (idx2 == string::npos) sport = lcurl.substr(idx1);
		else sport = lcurl.substr(idx1, idx2 - idx1);

		try {
			*port = (unsigned int) ::stoul(sport);
		}
		catch (...) {
			return 0;
		}
	}

	try {
		*server = new char[srv.length()+1];
	}
	catch (...) {
		return 0;
	}

	memcpy(*server, srv.c_str(), srv.length());
	(*server)[srv.length()] = 0;

	return 1;
}


#define NNL <<endl<<endl<<
#define NL <<endl<<

void usage ()
{
	cerr << "usage: sp [ options ] [ port ]" NL
"Required:" NL
"  -A, --ias-signing-cafile=FILE" NL
"                           Specify the IAS Report Signing CA file." NL
"  -C, --ias-cert-file=FILE Specify the IAS client certificate to use when" NL
"                             communicating with IAS." NNL
"One of (required):" NL
"  -S, --spid-file=FILE     Set the SPID from a file containg a 32-byte." NL
"                             ASCII hex string." NL
"  -s, --spid=HEXSTRING     Set the SPID from a 32-byte ASCII hex string." NNL
"Optional:" NL
"  -B, --ca-bundle-file=FILE" NL
"                           Use the CA certificate bundle at FILE (default:" NL
"                             " << DEFAULT_CA_BUNDLE << ")" NL
"  -E, --ias-cert-passwd=FILE" NL
"                           Use password in FILE for the IAS client" NL
"                             certificate." NL
"  -G, --list-agents        List available user agent names for --user-agent" NL
"  -K, --service-key-file=FILE" NL
"                           The private key file for the service in PEM" NL
"                             format (default: use hardcoded key). The " NL
"                             client must be given the corresponding public" NL
"                             key. Can't combine with --key." NL
"  -P, --production         Query the production IAS server instead of dev." NL
"  -X, --strict-trust-mode  Don't trust enclaves that receive a " NL
"                             CONFIGURATION_NEEDED response from IAS " NL
"                             (default: trust)" NL
"  -Y, --ias-cert-key=FILE  The private key file for the IAS client certificate." NL
"  -d, --debug              Print debug information to stderr." NL
"  -g, --user-agent=NAME    Use NAME as the user agent for contacting IAS." NL
"  -k, --key=HEXSTRING      The private key as a hex string. See --key-file" NL
"                             for notes. Can't combine with --key-file." NL
"  -l, --linkable           Request a linkable quote (default: unlinkable)." NL
"  -p, --proxy=PROXYURL     Use the proxy server at PROXYURL when contacting" NL
"                             IAS. Can't combine with --no-proxy\n" NL
"  -r, --api-version=N      Use version N of the IAS API (default: " << to_string(IAS_API_DEF_VERSION) << ")" NL
"  -t, --ias-cert-type=TYPE The client certificate type. Can be PEM (default)" NL
"                             or P12." NL
"  -v, --verbose            Be verbose. Print message structure details and the" NL
"                             results of intermediate operations to stderr." NL
"  -x, --no-proxy           Do not use a proxy (force a direct connection), " NL
"                             overriding environment." NL
"  -z  --stdio              Read from stdin and write to stdout instead of" NL
"                             running as a network server." <<endl;

}
