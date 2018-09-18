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

#include <openssl/err.h>

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

int encryptWithAES(unsigned char *plaintext, int plaintext_len, unsigned char *key,
  unsigned char *iv, unsigned char *ciphertext, unsigned char *tag);

// int encryptWithAES(unsigned char *plaintext, int plaintext_len, unsigned char *key,
//   unsigned char *iv, unsigned char *ciphertext);

int decryptWithAES(unsigned char *ciphertext, int ciphertext_len, unsigned char *tag,
	unsigned char *key, unsigned char *iv, unsigned char *plaintext);

// int decryptWithAES(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
//   unsigned char *iv, unsigned char *plaintext);

char debug = 0;
char verbose = 0;

int main(int argc, char *argv[])
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

	/* Command line options */

	static struct option long_opt[] =
	{
		{"ias-signing-cafile",
							required_argument,	0, 'A'},
		{"ca-bundle",		required_argument,	0, 'B'},
		{"ias-cert",		required_argument,	0, 'C'},
		{"ias-cert-passwd",
							required_argument,	0, 'E'},
		{"list-agents",		no_argument,		0, 'G'},
		{"service-key-file",
							required_argument,	0, 'K'},
		{"production",		no_argument,		0, 'P'},
		{"spid-file",		required_argument,	0, 'S'},
		{"strict-trust-mode",
							no_argument,		0, 'X'},
		{"ias-cert-key",
							required_argument,	0, 'Y'},
		{"debug",			no_argument,		0, 'd'},
		{"user-agent",		required_argument,	0, 'g'},
		{"help",			no_argument, 		0, 'h'},
		{"key",				required_argument,	0, 'k'},
		{"linkable",		no_argument,		0, 'l'},
		{"proxy",			required_argument,	0, 'p'},
		{"api-version",		required_argument,	0, 'r'},
		{"spid",			required_argument,	0, 's'},
		{"ias-cert-type",	required_argument,	0, 't'},
		{"verbose",			no_argument,		0, 'v'},
		{"no-proxy",		no_argument,		0, 'x'},
		{"stdio",			no_argument,		0, 'z'},
		{ 0, 0, 0, 0 }
	};

	/* Create a logfile to capture debug output and actual msg data */

	fplog = create_logfile("sp.log");
	fprintf(fplog, "Server log started\n");

	/* Config defaults */

	memset(&config, 0, sizeof(config));
#ifdef _WIN32
	strncpy_s((char *)config.cert_type, 4, "PEM", 3);
#else
	strncpy((char *)config.cert_type, "PEM", 3);
#endif
	config.apiver= IAS_API_DEF_VERSION;

	/* Parse our options */

	while (1) {
		int c;
		int opt_index = 0;

		c = getopt_long(argc, argv, "A:B:C:E:GK:PS:XY:dg:hk:lp:r:s:t:vxz", long_opt, &opt_index);
		if (c == -1) break;

		switch (c) {
		case 0:
			break;
		case 'A':
			if (!cert_load_file(&config.signing_ca, optarg)) {
				crypto_perror("cert_load_file");
				eprintf("%s: could not load IAS Signing Cert CA\n", optarg);
				return 1;
			}

			config.store = cert_init_ca(config.signing_ca);
			if (config.store == NULL) {
				eprintf("%s: could not initialize certificate store\n", optarg);
				return 1;
			}
			++flag_ca;

			break;
		case 'B':
			config.ca_bundle = strdup(optarg);
			if (config.ca_bundle == NULL) {
				perror("strdup");
				return 1;
			}

			break;
		case 'C':
			config.cert_file = strdup(optarg);
			if (config.cert_file == NULL) {
				perror("strdup");
				return 1;
			}
			++flag_cert;

			break;
		case 'E':
			config.cert_passwd_file = strdup(optarg);
			if (config.cert_passwd_file == NULL) {
				perror("strdup");
				return 1;
			}
			break;
		case 'G':
			ias_list_agents(stdout);
			return 1;

                case 'P':
                        flag_prod = 1;
                        break;

		case 'S':
			if (!from_hexstring_file((unsigned char *)&config.spid, optarg, 16)) {
				eprintf("SPID must be 32-byte hex string\n");
				return 1;
			}
			++flag_spid;

			break;
		case 'K':
			if (!key_load_file(&config.service_private_key, optarg, KEY_PRIVATE)) {
				crypto_perror("key_load_file");
				eprintf("%s: could not load EC private key\n", optarg);
				return 1;
			}
			break;
		case 'X':
			config.strict_trust= 1;
			break;
		case 'Y':
			config.cert_key_file = strdup(optarg);
			if (config.cert_key_file == NULL) {
				perror("strdup");
				return 1;
			}
			break;
		case 'd':
			debug = 1;
			break;
		case 'g':
			config.user_agent= strdup(optarg);
			if ( config.user_agent == NULL ) {
				perror("malloc");
				return 1;
			}
			break;
		case 'k':
			if (!key_load(&config.service_private_key, optarg, KEY_PRIVATE)) {
				crypto_perror("key_load");
				eprintf("%s: could not load EC private key\n", optarg);
				return 1;
			}
			break;
		case 'l':
			config.quote_type = SGX_LINKABLE_SIGNATURE;
			break;
		case 'p':
			if ( flag_noproxy ) usage();
			if (!get_proxy(&config.proxy_server, &config.proxy_port, optarg)) {
				eprintf("%s: could not extract proxy info\n", optarg);
				return 1;
			}
			// Break the URL into host and port. This is a simplistic algorithm.
			break;
		case 'r':
			config.apiver= atoi(optarg);
			if ( config.apiver < IAS_MIN_VERSION || config.apiver >
				IAS_MAX_VERSION ) {

				eprintf("version must be between %d and %d\n",
					IAS_MIN_VERSION, IAS_MAX_VERSION);
				return 1;
			}
			break;
		case 's':
			if (strlen(optarg) < 32) {
				eprintf("SPID must be 32-byte hex string\n");
				return 1;
			}
			if (!from_hexstring((unsigned char *)&config.spid, (unsigned char *)optarg, 16)) {
				eprintf("SPID must be 32-byte hex string\n");
				return 1;
			}
			++flag_spid;
			break;
		case 't':
			strncpy((char *) config.cert_type, optarg, 4);
			if ( debug ) eprintf("+++ cert type set to %s\n",
				config.cert_type);
			break;
		case 'v':
			verbose = 1;
			break;
		case 'x':
			if ( config.proxy_server != NULL ) usage();
			flag_noproxy=1;
			break;
		case 'z':
			flag_stdio= 1;
			break;
		case 'h':
		case '?':
		default:
			usage();
		}
	}

	/* We should have zero or one command-line argument remaining */

	argc-= optind;
	if ( argc > 1 ) usage();

	/* The remaining argument, if present, is the port number. */

	if ( flag_stdio && argc ) {
		usage();
	} else if ( argc ) {
		port= argv[optind];
	} else {
		port= strdup(DEFAULT_PORT);
		if ( port == NULL ) {
			perror("strdup");
			return 1;
		}
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

	if (debug) {
		eprintf("+++ using private key:\n");
		PEM_write_PrivateKey(stderr, config.service_private_key, NULL,
			NULL, 0, 0, NULL);
		PEM_write_PrivateKey(fplog, config.service_private_key, NULL,
			NULL, 0, 0, NULL);
	}

	if (!flag_spid) {
		eprintf("--spid or --spid-file is required\n");
		flag_usage = 1;
	}

	if (!flag_cert) {
		eprintf("--ias-cert-file is required\n");
		flag_usage = 1;
	}

	if (!flag_ca) {
		eprintf("--ias-signing-cafile is required\n");
		flag_usage = 1;
	}

	if (flag_usage) usage();

	if (verbose) eprintf("Using cert file %s\n", config.cert_file);

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

	ias->client_cert(config.cert_file, (char *)config.cert_type);
	if ( config.cert_passwd_file != NULL ) {
		char *passwd;
		char *keyfile;
		off_t sz;

		if ( ! from_file(NULL, config.cert_passwd_file, &sz) ) {
			eprintf("can't load password from %s\n",
				config.cert_passwd_file);
			return 1;
		}

		if ( sz > 0 ) {
			char *cp;

			try {
				passwd= new char[sz+1];
			}
			catch (...) {
				eprintf("out of memory\n");
				return 1;
			}

			if ( ! from_file((unsigned char *) passwd, config.cert_passwd_file,
			 	&sz) ) {

				eprintf("can't load password from %s\n",
					config.cert_passwd_file);
				return 1;
			}
			passwd[sz]= 0;

			// Remove trailing newline or linefeed.

			cp= strchr(passwd, '\n');
			if ( cp != NULL ) *cp= 0;
			cp= strchr(passwd, '\r');
			if ( cp != NULL ) *cp= 0;

			// If a key file isn't specified, assume it's bundled with
			// the certificate.

			keyfile= (config.cert_key_file == NULL) ? config.cert_file :
				config.cert_key_file;
			if ( debug ) eprintf("+++ using cert key file %s\n", keyfile);
			ias->client_key(keyfile, passwd);

#ifdef _WIN32
			SecureZeroMemory(passwd, sz);
#else
			// -fno-builtin-memset prevents optimizing this away
			memset(passwd, 0, sz);
#endif
		}
	} else if ( config.cert_key_file != NULL ) {
		// We have a key file but no password.
		ias->client_key(config.cert_key_file, NULL);
	}

	if ( flag_noproxy ) ias->proxy_mode(IAS_PROXY_NONE);
	else if (config.proxy_server != NULL) {
		ias->proxy_mode(IAS_PROXY_FORCE);
		ias->proxy(config.proxy_server, config.proxy_port);
	}

	if ( config.user_agent != NULL ) {
		if ( ! ias->agent(config.user_agent) ) {
			eprintf("%s: unknown user agent\n", config.user_agent);
			return 0;
		}
	}

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

	/* Get our message IO object. */

	if ( flag_stdio ) {
		msgio= new MsgIO();
	} else {
		try {
			msgio= new MsgIO(NULL, (port == NULL) ? DEFAULT_PORT : port);
		}
		catch(...) {
			return 1;
		}
	}

 	/* If we're running in server mode, we'll block here.  */

	while ( msgio->server_loop() ) {
		sgx_ra_msg1_t msg1;
		sgx_ra_msg2_t msg2;
		ra_msg4_t msg4;
		unsigned char smk[16], sk[16], mk[16];

		/* Read message 0 and 1, then generate message 2 */

		if ( ! process_msg01(msgio, ias, &msg1, &msg2, &sigrl, &config, smk) ) {
			eprintf("error processing msg1\n");
			goto disconnect;
		}

		/* Send message 2 */

		/*
	 	* sgx_ra_msg2_t is a struct with a flexible array member at the
	 	* end (defined as uint8_t sig_rl[]). We could go to all the
	 	* trouble of building a byte array large enough to hold the
	 	* entire struct and then cast it as (sgx_ra_msg2_t) but that's
	 	* a lot of work for no gain when we can just send the fixed
	 	* portion and the array portion by hand.
	 	*/

		dividerWithText(stderr, "Copy/Paste Msg2 Below to Client");
		dividerWithText(fplog, "Msg2 (send to Client)");

		msgio->send_partial((void *) &msg2, sizeof(sgx_ra_msg2_t));
		fsend_msg_partial(fplog, (void *) &msg2, sizeof(sgx_ra_msg2_t));

		msgio->send(&msg2.sig_rl, msg2.sig_rl_size);
		fsend_msg(fplog, &msg2.sig_rl, msg2.sig_rl_size);

		edivider();

		/* Read message 3, and generate message 4 */

		if ( ! process_msg3(msgio, ias, &msg1, &msg4, &config, smk, mk, sk) ) {
			eprintf("error processing msg3\n");
			goto disconnect;
		}

disconnect:
		msgio->disconnect();
	}

	crypto_destroy();

	return 0;
}

int process_msg3 (MsgIO *msgio, IAS_Connection *ias, sgx_ra_msg1_t *msg1,
	ra_msg4_t *msg4, config_t *config, unsigned char smk[16],
	unsigned char mk[16], unsigned char sk[16])
{
	sgx_ra_msg3_t *msg3;
	size_t blen= 0;
	size_t sz;
	int rv;
	uint32_t quote_sz;
	char *buffer= NULL;
	char *b64quote;
	sgx_mac_t vrfymac;
	sgx_quote_t *q;

	/*
	 * Read our incoming message. We're using base16 encoding/hex strings
	 * so we should end up with sizeof(msg)*2 bytes.
	 */

	fprintf(stderr, "Waiting for msg3\n");

	/*
	 * Read message 3
	 *
	 * CMACsmk(M) || M
	 *
	 * where
	 *
	 * M = ga || PS_SECURITY_PROPERTY || QUOTE
	 *
	 */

	rv= msgio->read((void **) &msg3, &sz);
	if ( rv == -1 ) {
		eprintf("system error reading msg3\n");
		return 0;
	} else if ( rv == 0 ) {
		eprintf("protocol error reading msg3\n");
		return 0;
	}
	if ( debug ) {
		eprintf("+++ read %lu bytes\n", sz);
	}

	/*
	 * The quote size will be the total msg3 size - sizeof(sgx_ra_msg3_t)
	 * since msg3.quote is a flexible array member.
	 *
	 * Total message size is sz/2 since the income message is in base16.
	 */
	quote_sz = (uint32_t)((sz / 2) - sizeof(sgx_ra_msg3_t));
	if ( debug ) {
		eprintf("+++ quote_sz= %lu bytes\n", quote_sz);
	}

	/* Make sure Ga matches msg1 */

	if ( debug ) {
		eprintf("+++ Verifying msg3.g_a matches msg1.g_a\n");
		eprintf("msg1.g_a.gx = %s\n",
			hexstring(msg3->g_a.gx, sizeof(msg1->g_a.gx)));
		eprintf("msg1.g_a.gy = %s\n",
			hexstring(&msg3->g_a.gy, sizeof(msg1->g_a.gy)));
		eprintf("msg3.g_a.gx = %s\n",
			hexstring(msg3->g_a.gx, sizeof(msg3->g_a.gx)));
		eprintf("msg3.g_a.gy = %s\n",
			hexstring(&msg3->g_a.gy, sizeof(msg3->g_a.gy)));
	}
	if ( CRYPTO_memcmp(&msg3->g_a, &msg1->g_a, sizeof(sgx_ec256_public_t)) ) {
		eprintf("msg1.g_a and mgs3.g_a keys don't match\n");
		return 0;
	}

	/* Validate the MAC of M */

	cmac128(smk, (unsigned char *) &msg3->g_a,
		sizeof(sgx_ra_msg3_t)-sizeof(sgx_mac_t)+quote_sz,
		(unsigned char *) vrfymac);
	if ( debug ) {
		eprintf("+++ Validating MACsmk(M)\n");
		eprintf("msg3.mac   = %s\n", hexstring(msg3->mac, sizeof(sgx_mac_t)));
		eprintf("calculated = %s\n", hexstring(vrfymac, sizeof(sgx_mac_t)));
	}
	if ( CRYPTO_memcmp(msg3->mac, vrfymac, sizeof(sgx_mac_t)) ) {
		eprintf("Failed to verify msg3 MAC\n");
		return 0;
	}

	/* Encode the report body as base64 */

	b64quote= base64_encode((char *) &msg3->quote, quote_sz);
	q= (sgx_quote_t *) msg3->quote;

	if ( verbose ) {

		edividerWithText("Msg3 Details (from Client)");
		eprintf("msg3.mac                 = %s\n",
			hexstring(&msg3->mac, sizeof(msg3->mac)));
		eprintf("msg3.g_a.gx              = %s\n",
			hexstring(msg3->g_a.gx, sizeof(msg3->g_a.gx)));
		eprintf("msg3.g_a.gy              = %s\n",
			hexstring(&msg3->g_a.gy, sizeof(msg3->g_a.gy)));
		eprintf("msg3.ps_sec_prop         = %s\n",
			hexstring(&msg3->ps_sec_prop, sizeof(msg3->ps_sec_prop)));
		eprintf("msg3.quote.version       = %s\n",
			hexstring(&q->version, sizeof(uint16_t)));
		eprintf("msg3.quote.sign_type     = %s\n",
			hexstring(&q->sign_type, sizeof(uint16_t)));
		eprintf("msg3.quote.epd_group_id  = %s\n",
			hexstring(&q->epid_group_id, sizeof(sgx_epid_group_id_t)));
		eprintf("msg3.quote.qe_svn        = %s\n",
			hexstring(&q->qe_svn, sizeof(sgx_isv_svn_t)));
		eprintf("msg3.quote.pce_svn       = %s\n",
			hexstring(&q->pce_svn, sizeof(sgx_isv_svn_t)));
		eprintf("msg3.quote.xeid          = %s\n",
			hexstring(&q->xeid, sizeof(uint32_t)));
		eprintf("msg3.quote.basename      = %s\n",
			hexstring(&q->basename, sizeof(sgx_basename_t)));
		eprintf("msg3.quote.report_body   = %s\n",
			hexstring(&q->report_body, sizeof(sgx_report_body_t)));
		eprintf("msg3.quote.signature_len = %s\n",
			hexstring(&q->signature_len, sizeof(uint32_t)));
		eprintf("msg3.quote.signature     = %s\n",
			hexstring(&q->signature, q->signature_len));

		edividerWithText("Enclave Quote (base64) ==> Send to IAS");

		eputs(b64quote);

		eprintf("\n");
		edivider();
	}

	if ( get_attestation_report(ias, config->apiver, b64quote,
		msg3->ps_sec_prop, msg4, config->strict_trust) ) {

		sgx_report_body_t *r= (sgx_report_body_t *) &q->report_body;

		/*
		 * A real service provider would validate that the enclave
		 * report is from an enclave that they recognize. Namely,
		 * that the MRSIGNER matches our signing key, and the MRENCLAVE
		 * hash matches an enclave that we compiled.
		 *
		 * Other policy decisions might include examining ISV_SVN to
		 * prevent outdated/deprecated software from successfully
		 * attesting, and ensuring the TCB is not out of date.
		 */

		if ( verbose ) {
			edivider();

			// The enclave report is valid so we can trust the report
			// data.

			edividerWithText("Enclave Report Details");

			eprintf("cpu_svn     = %s\n",
				hexstring(&r->cpu_svn, sizeof(sgx_cpu_svn_t)));
			eprintf("misc_select = %s\n",
				hexstring(&r->misc_select, sizeof(sgx_misc_select_t)));
			eprintf("attributes  = %s\n",
				hexstring(&r->attributes, sizeof(sgx_attributes_t)));
			eprintf("mr_enclave  = %s\n",
				hexstring(&r->mr_enclave, sizeof(sgx_measurement_t)));
			eprintf("mr_signer   = %s\n",
				hexstring(&r->mr_signer, sizeof(sgx_measurement_t)));
			eprintf("isv_prod_id = %04hX\n", r->isv_prod_id);
			eprintf("isv_svn     = %04hX\n", r->isv_svn);
			eprintf("report_data = %s\n",
				hexstring(&r->report_data, sizeof(sgx_report_data_t)));
		}


		edividerWithText("Copy/Paste Msg4 Below to Client");

		/* Serialize the members of the Msg4 structure independently */
		/* vs. the entire structure as one send_msg() */

		msgio->send_partial(&msg4->status, sizeof(msg4->status));
		msgio->send(&msg4->platformInfoBlob, sizeof(msg4->platformInfoBlob));

		fsend_msg_partial(fplog, &msg4->status, sizeof(msg4->status));
		fsend_msg(fplog, &msg4->platformInfoBlob,
			sizeof(msg4->platformInfoBlob));
		edivider();

		/*
		 * If the enclave is trusted, derive the MK and SK. Also get
		 * SHA256 hashes of these so we can verify there's a shared
		 * secret between us and the client.
		 */

		if ( msg4->status == Trusted ) {
			unsigned char hashmk[32], hashsk[32];

			if ( debug ) eprintf("+++ Deriving the MK and SK\n");
			cmac128(config->kdk, (unsigned char *)("\x01MK\x00\x80\x00"),
				6, mk);
			cmac128(config->kdk, (unsigned char *)("\x01SK\x00\x80\x00"),
				6, sk);

			sha256_digest(mk, 16, hashmk);
			sha256_digest(sk, 16, hashsk);

			if ( verbose ) {
				eprintf("MK         = %s\n", hexstring(mk, 16));
				eprintf("SK         = %s\n", hexstring(sk, 16));
				eprintf("SHA256(MK) = %s\n", hexstring(hashmk, 32));
				eprintf("SHA256(SK) = %s\n", hexstring(hashsk, 32));
			}

			// Encrypt and decrypt based on
			// https://wiki.openssl.org/index.php/EVP_Authenticated_Encryption_and_Decryption
			// https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption

			unsigned char* key = mk;
			// FIXME: Use random (not necessarily secret) IV
		  unsigned char* iv = (unsigned char *) "012345678901";
			unsigned char* plaintext = (unsigned char*) "Hello, Ankr!";
			unsigned char ciphertext[128];
			unsigned char tag[128];
			unsigned char decryptedtext[128];
			unsigned char decryptedtext_from_sgx[128];
			int decryptedtext_len, ciphertext_len;

			eprintf("Plaintext: %s\n", plaintext);

			ciphertext_len = encryptWithAES(plaintext, strlen ((char *)plaintext), key, iv,
      									ciphertext, tag);

			eprintf("Ciphertext: %s\n", hexstring(ciphertext, ciphertext_len));

			decryptedtext_len = decryptWithAES(ciphertext, ciphertext_len, tag, key, iv,
    												decryptedtext);

			decryptedtext[decryptedtext_len] = '\0';
			eprintf("Decrypted text: %s\n", decryptedtext);

			eprintf("Secure communication w/ the remote SGX enclave.\n");


			unsigned char *p_ciphertext_from_sgx;
			size_t ciphertext_from_sgx_len = -1;

			int read_ret = msgio->read((void**) &p_ciphertext_from_sgx, &ciphertext_from_sgx_len);

			if (read_ret != 1) {
				eprintf("Error while receiving from remote SGX enclave: %d\n", read_ret);
			} else {
				eprintf("Successfully received %d bytes from remote SGX enclave.\n", ciphertext_from_sgx_len);
			}

			eprintf("Ciphertext from remote SGX enclave: %s\n", hexstring(p_ciphertext_from_sgx, ciphertext_from_sgx_len/2));

			unsigned char *p_mac;
			size_t p_mac_len;

			read_ret = msgio->read((void**) &p_mac, &p_mac_len);

			if (read_ret != 1) {
				eprintf("Error while receiving MAC from remote SGX enclave: %d\n", read_ret);
			} else {
				eprintf("Successfully received %d bytes for MAC from remote SGX enclave.\n", p_mac_len);
			}

			eprintf("MAC from remote SGX enclave: %s\n", hexstring(p_mac, p_mac_len/2));


			int decryptedtext_from_sgx_len = decryptWithAES(
														p_ciphertext_from_sgx,
														ciphertext_from_sgx_len/2,
														p_mac, key, iv,
    												decryptedtext_from_sgx);

			if (decryptedtext_from_sgx_len == -1) {
				eprintf("Error while decrypting text from SGX: %d\n", decryptedtext_from_sgx_len);
			} else {
				eprintf("Decrypted %d characters of text from SGX\n", decryptedtext_from_sgx_len);
				decryptedtext_from_sgx[decryptedtext_from_sgx_len] = '\0';
				eprintf("Decrypted text from SGX: %s\n", decryptedtext_from_sgx);
			}
		}

	} else {
		eprintf("Attestation failed\n");
	}

	free(b64quote);

	return 1;
}

void handleErrors(void)
{
  ERR_print_errors_fp(stderr);
  abort();
}

int encryptWithAES(unsigned char *plaintext, int plaintext_len, unsigned char *key,
  unsigned char *iv, unsigned char *ciphertext, unsigned char *tag)
{
	EVP_CIPHER_CTX *ctx;

	int len;

	int ciphertext_len;


	/* Create and initialise the context */
	if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

	/* Initialise the encryption operation. */
	if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL))
		handleErrors();

	// /* Set IV length if default 12 bytes (96 bits) is not appropriate */
	// if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL))
	// 	handleErrors();

	/* Initialise key and IV */
	if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)) handleErrors();

	// /* Provide any AAD data. This can be called zero or more times as
	//  * required
	//  */
	// if(1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len))
	// 	handleErrors();

	/* Provide the message to be encrypted, and obtain the encrypted output.
	 * EVP_EncryptUpdate can be called multiple times if necessary
	 */
	if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
		handleErrors();
	ciphertext_len = len;

	/* Finalise the encryption. Normally ciphertext bytes may be written at
	 * this stage, but this does not occur in GCM mode
	 */
	if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
	ciphertext_len += len;

	/* Get the tag */
	if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag))
		handleErrors();

	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);

	return ciphertext_len;
}

int encryptWithAESCBC(unsigned char *plaintext, int plaintext_len, unsigned char *key,
  unsigned char *iv, unsigned char *ciphertext)
{
  EVP_CIPHER_CTX *ctx;

  int len;

  int ciphertext_len;

  /* Create and initialise the context */
  if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

  /* Initialise the encryption operation. IMPORTANT - ensure you use a key
   * and IV size appropriate for your cipher
   * In this example we are using 128 bit AES (i.e. a 128 bit key). The
   * IV size for *most* modes is the same as the block size. For AES this
   * is 128 bits */
  if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    handleErrors();

  /* Provide the message to be encrypted, and obtain the encrypted output.
   * EVP_EncryptUpdate can be called multiple times if necessary
   */
  if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
    handleErrors();
  ciphertext_len = len;

  /* Finalise the encryption. Further ciphertext bytes may be written at
   * this stage.
   */
  if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
  ciphertext_len += len;

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  return ciphertext_len;
}

int decryptWithAES(unsigned char *ciphertext, int ciphertext_len, unsigned char *tag,
	unsigned char *key, unsigned char *iv, unsigned char *plaintext)
{
	EVP_CIPHER_CTX *ctx;
	int len;
	int plaintext_len;
	int ret;

	/* Create and initialise the context */
	if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

	/* Initialise the decryption operation. */
	if(!EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL))
		handleErrors();

	// /* Set IV length. Not necessary if this is 12 bytes (96 bits) */
	// if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL))
	// 	handleErrors();

	/* Initialise key and IV */
	if(!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)) handleErrors();

	// /* Provide any AAD data. This can be called zero or more times as
	//  * required
	//  */
	// if(!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len))
	// 	handleErrors();

	/* Provide the message to be decrypted, and obtain the plaintext output.
	 * EVP_DecryptUpdate can be called multiple times if necessary
	 */
	if(!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
		handleErrors();
	plaintext_len = len;

	/* Set expected tag value. Works in OpenSSL 1.0.1d and later */
	if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag))
		handleErrors();

	/* Finalise the decryption. A positive return value indicates success,
	 * anything else is a failure - the plaintext is not trustworthy.
	 */
	ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);

	if(ret > 0)
	{
		/* Success */
		plaintext_len += len;
		return plaintext_len;
	}
	else
	{
		/* Verify failed */
		return -1;
	}
}

int decryptWithAESCBC(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
  unsigned char *iv, unsigned char *plaintext)
{
  EVP_CIPHER_CTX *ctx;

  int len;

  int plaintext_len;

  /* Create and initialise the context */
  if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

  /* Initialise the decryption operation. IMPORTANT - ensure you use a key
   * and IV size appropriate for your cipher
   * In this example we are using 128 bit AES (i.e. a 128 bit key). The
   * IV size for *most* modes is the same as the block size. For AES this
   * is 128 bits */
  if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    handleErrors();

  /* Provide the message to be decrypted, and obtain the plaintext output.
   * EVP_DecryptUpdate can be called multiple times if necessary
   */
  if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
    handleErrors();
  plaintext_len = len;

  /* Finalise the decryption. Further plaintext bytes may be written at
   * this stage.
   */
  if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) handleErrors();
  plaintext_len += len;

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  return plaintext_len;
}

/*
 * Read and process message 0 and message 1. These messages are sent by
 * the client concatenated together for efficiency (msg0||msg1).
 */

int process_msg01 (MsgIO *msgio, IAS_Connection *ias, sgx_ra_msg1_t *msg1,
	sgx_ra_msg2_t *msg2, char **sigrl, config_t *config, unsigned char smk[16])
{
	struct msg01_struct {
		uint32_t msg0_extended_epid_group_id;
		sgx_ra_msg1_t msg1;
	} *msg01;
	size_t blen= 0;
	char *buffer= NULL;
	unsigned char gb_ga[128];
	unsigned char digest[32], r[32], s[32];
	EVP_PKEY *Gb;
	int rv;

	memset(msg2, 0, sizeof(sgx_ra_msg2_t));

	/*
	 * Read our incoming message. We're using base16 encoding/hex strings
	 * so we should end up with sizeof(msg)*2 bytes.
	 */

	fprintf(stderr, "Waiting for msg0||msg1\n");

	rv= msgio->read((void **) &msg01, NULL);
	if ( rv == -1 ) {
		eprintf("system error reading msg0||msg1\n");
		return 0;
	} else if ( rv == 0 ) {
		eprintf("protocol error reading msg0||msg1\n");
		return 0;
	}

	if ( verbose ) {
		edividerWithText("Msg0 Details (from Client)");
		eprintf("msg0.extended_epid_group_id = %u\n",
			 msg01->msg0_extended_epid_group_id);
		edivider();
	}

	/* According to the Intel SGX Developer Reference
	 * "Currently, the only valid extended Intel(R) EPID group ID is zero. The
	 * server should verify this value is zero. If the Intel(R) EPID group ID
	 * is not zero, the server aborts remote attestation"
	 */

	if ( msg01->msg0_extended_epid_group_id != 0 ) {
		eprintf("msg0 Extended Epid Group ID is not zero.  Exiting.\n");
		free(msg01);
		return 0;
	}

	// Pass msg1 back to the pointer in the caller func
	memcpy(msg1, &msg01->msg1, sizeof(sgx_ra_msg1_t));

	if ( verbose ) {
		edividerWithText("Msg1 Details (from Client)");
		eprintf("msg1.g_a.gx = %s\n",
			hexstring(&msg1->g_a.gx, sizeof(msg1->g_a.gx)));
		eprintf("msg1.g_a.gy = %s\n",
			hexstring(&msg1->g_a.gy, sizeof(msg1->g_a.gy)));
		eprintf("msg1.gid    = %s\n",
			hexstring( &msg1->gid, sizeof(msg1->gid)));
		edivider();
	}

	/* Generate our session key */

	if ( debug ) eprintf("+++ generating session key Gb\n");

	Gb= key_generate();
	if ( Gb == NULL ) {
		eprintf("Could not create a session key\n");
		free(msg01);
		return 0;
	}

	/*
	 * Derive the KDK from the key (Ga) in msg1 and our session key.
	 * An application would normally protect the KDK in memory to
	 * prevent trivial inspection.
	 */

	if ( debug ) eprintf("+++ deriving KDK\n");

	if ( ! derive_kdk(Gb, config->kdk, msg1, config) ) {
		eprintf("Could not derive the KDK\n");
		free(msg01);
		return 0;
	}

	if ( debug ) eprintf("+++ KDK = %s\n", hexstring( config->kdk, 16));

	/*
 	 * Derive the SMK from the KDK
	 * SMK = AES_CMAC(KDK, 0x01 || "SMK" || 0x00 || 0x80 || 0x00)
	 */

	if ( debug ) eprintf("+++ deriving SMK\n");

	cmac128(config->kdk, (unsigned char *)("\x01SMK\x00\x80\x00"), 7, smk);

	if ( debug ) eprintf("+++ SMK = %s\n", hexstring(smk, 16));

	/*
	 * Build message 2
	 *
	 * A || CMACsmk(A) || SigRL
	 * (148 + 16 + SigRL_length bytes = 164 + SigRL_length bytes)
	 *
	 * where:
	 *
	 * A      = Gb || SPID || TYPE || KDF-ID || SigSP(Gb, Ga)
	 *          (64 + 16 + 2 + 2 + 64 = 148 bytes)
	 * Ga     = Client enclave's session key
	 *          (32 bytes)
	 * Gb     = Service Provider's session key
	 *          (32 bytes)
	 * SPID   = The Service Provider ID, issued by Intel to the vendor
	 *          (16 bytes)
	 * TYPE   = Quote type (0= linkable, 1= linkable)
	 *          (2 bytes)
	 * KDF-ID = (0x0001= CMAC entropy extraction and key derivation)
	 *          (2 bytes)
	 * SigSP  = ECDSA signature of (Gb.x || Gb.y || Ga.x || Ga.y) as r || s
	 *          (signed with the Service Provider's private key)
	 *          (64 bytes)
	 *
	 * CMACsmk= AES-128-CMAC(A)
	 *          (16 bytes)
	 *
	 * || denotes concatenation
	 *
	 * Note that all key components (Ga.x, etc.) are in little endian
	 * format, meaning the byte streams need to be reversed.
	 *
	 * For SigRL, send:
	 *
	 *  SigRL_size || SigRL_contents
	 *
	 * where sigRL_size is a 32-bit uint (4 bytes). This matches the
	 * structure definition in sgx_ra_msg2_t
	 */

	key_to_sgx_ec256(&msg2->g_b, Gb);
	memcpy(&msg2->spid, &config->spid, sizeof(sgx_spid_t));
	msg2->quote_type= config->quote_type;
	msg2->kdf_id= 1;

	/* Get the sigrl */

	if ( ! get_sigrl(ias, config->apiver, msg1->gid, sigrl,
		&msg2->sig_rl_size) ) {

		eprintf("could not retrieve the sigrl\n");
		return 0;
	}

	memcpy(gb_ga, &msg2->g_b, 64);
	memcpy(&gb_ga[64], &msg1->g_a, 64);

	if ( debug ) eprintf("+++ GbGa = %s\n", hexstring(gb_ga, 128));

	ecdsa_sign(gb_ga, 128, config->service_private_key, r, s, digest);
	reverse_bytes(&msg2->sign_gb_ga.x, r, 32);
	reverse_bytes(&msg2->sign_gb_ga.y, s, 32);

	if ( debug ) {
		eprintf("+++ sha256(GbGa) = %s\n", hexstring(digest, 32));
		eprintf("+++ r = %s\n", hexstring(r, 32));
		eprintf("+++ s = %s\n", hexstring(s, 32));
	}

	/* The "A" component is conveniently at the start of sgx_ra_msg2_t */

	cmac128(smk, (unsigned char *) msg2, 148, (unsigned char *) &msg2->mac);

	if ( verbose ) {
		edividerWithText("Msg2 Details");
		eprintf("msg2.g_b.gx      = %s\n",
			hexstring(&msg2->g_b.gx, sizeof(msg2->g_b.gx)));
		eprintf("msg2.g_b.gy      = %s\n",
			hexstring(&msg2->g_b.gy, sizeof(msg2->g_b.gy)));
		eprintf("msg2.spid        = %s\n",
			hexstring(&msg2->spid, sizeof(msg2->spid)));
		eprintf("msg2.quote_type  = %s\n",
			hexstring(&msg2->quote_type, sizeof(msg2->quote_type)));
		eprintf("msg2.kdf_id      = %s\n",
			hexstring(&msg2->kdf_id, sizeof(msg2->kdf_id)));
		eprintf("msg2.sign_ga_gb  = %s\n",
			hexstring(&msg2->sign_gb_ga, sizeof(msg2->sign_gb_ga)));
		eprintf("msg2.mac         = %s\n",
			hexstring(&msg2->mac, sizeof(msg2->mac)));
		eprintf("msg2.sig_rl_size = %s\n",
			hexstring(&msg2->sig_rl_size, sizeof(msg2->sig_rl_size)));
		edivider();
	}

	free(msg01);

	return 1;
}

int derive_kdk(EVP_PKEY *Gb, unsigned char kdk[16], sgx_ra_msg1_t *msg1,
	config_t *config)
{
	unsigned char *Gab_x;
	size_t slen;
	EVP_PKEY *Ga;
	unsigned char cmackey[16];

	memset(cmackey, 0, 16);

	/*
	 * Compute the shared secret using the peer's public key and a generated
	 * public/private key.
	 */

	Ga= key_from_sgx_ec256(&msg1->g_a);
	if ( Ga == NULL ) {
		crypto_perror("key_from_sgx_ec256");
		return 0;
	}

	/* The shared secret in a DH exchange is the x-coordinate of Gab */
	Gab_x= key_shared_secret(Gb, Ga, &slen);
	if ( Gab_x == NULL ) {
		crypto_perror("key_shared_secret");
		return 0;
	}

	/* We need it in little endian order, so reverse the bytes. */
	/* We'll do this in-place. */

	if ( debug ) eprintf("+++ shared secret= %s\n", hexstring(Gab_x, slen));

	reverse_bytes(Gab_x, Gab_x, slen);

	if ( debug ) eprintf("+++ reversed     = %s\n", hexstring(Gab_x, slen));

	/* Now hash that to get our KDK (Key Definition Key) */

	/*
	 * KDK = AES_CMAC(0x00000000000000000000000000000000, secret)
	 */

	cmac128(cmackey, Gab_x, slen, kdk);

	return 1;
}

int get_sigrl (IAS_Connection *ias, int version, sgx_epid_group_id_t gid,
	char **sig_rl, uint32_t *sig_rl_size)
{
	IAS_Request *req= NULL;
	int oops= 1;
	string sigrlstr;

	try {
		oops= 0;
		req= new IAS_Request(ias, (uint16_t) version);
	}
	catch (...) {
		oops = 1;
	}

	if (oops) {
		eprintf("Exception while creating IAS request object\n");
		return 0;
	}

	if ( req->sigrl(*(uint32_t *) gid, sigrlstr) != IAS_OK ) {
		return 0;
	}

	*sig_rl= strdup(sigrlstr.c_str());
	if ( *sig_rl == NULL ) return 0;

	*sig_rl_size= (uint32_t ) sigrlstr.length();

	return 1;
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

	::exit(1);
}
