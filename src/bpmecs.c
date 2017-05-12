/*
 * This openSSL engine is developed by
 * Peter Spacek and Pavol Zajac, FEI STU BA
 * as master project.
 *
 */

#include "mceliece.h"
#include <stdio.h>
#include <string.h>
#include <openssl/opensslv.h>
#include <openssl/opensslconf.h>
#include <openssl/crypto.h>
#include <openssl/objects.h>
#include <openssl/engine.h>
#include <openssl/evp.h>

#ifndef ENGINE_CMD_BASE
#error did not get engine.h
#endif


static const char *engine_id ="bpmecs";
static const char *engine_name ="bitpuch mceliece engine";

static RSA_METHOD mecs =
{
  "McEliece",
  /* encrypt */
  bpmecs_encrypt,
  bpmecs_encrypt,
//  NULL,
  bpmecs_decrypt,
 // NULL,
  /* decrypt */
  bpmecs_decrypt,
  NULL,
  NULL,
  NULL,
  NULL,
  0,
  NULL,
  NULL,
  NULL,
  bpmecs_keygen
};

static int bpmecs_destroy(ENGINE * e);
static int register_pmeth_bpmecs(int id, EVP_PKEY_METHOD **pmeth, int flags);
static int bpmecs_pkey_meths(ENGINE *e, EVP_PKEY_METHOD **pmeth, const int **nids, int nid);

/* Destructor */
static int bpmecs_destroy(ENGINE * e)
{
	(void)e;
	return 1;
}


static int bind_helper(ENGINE * e)
{
	if (!ENGINE_set_id(e, engine_id)) {
      fprintf(stderr, "ENGINE_set_id failed\n");
      return 0;
    }

	if (!ENGINE_set_name(e, engine_name)) {
      fprintf(stderr, "ENGINE_set_name failed\n");
      return 0;
    }

	if (!ENGINE_set_init_function(e, bpmecs_init) ) {
      fprintf(stderr, "ENGINE_set_init_function failed\n");
      return 0;
    }

	if (!ENGINE_set_destroy_function(e, bpmecs_destroy) ) {
      fprintf(stderr, "ENGINE_set_destroy_function failed\n");
      return 0;
    }

	if (!ENGINE_set_finish_function(e, bpmecs_finish) ) {
      fprintf(stderr, "ENGINE_set_finish_function failed\n");
      return 0;
    }
/*
    if (!ENGINE_set_ctrl_function(e, bpmecs_crtl)) {
      fprintf(stderr,"ENGINE_ctrl_function failed\n");
      return 0;
    }*/

    if (!ENGINE_set_load_privkey_function(e, bpmecs_load_key)) {
      fprintf(stderr,"ENGINE_set_load_privkey_function failed \n");
      return 0;
    }

    if (!ENGINE_set_load_pubkey_function(e, bpmecs_load_key)) {
      fprintf(stderr,"ENGINE_set_load_pubkey_function failed \n");
      return 0;
    }

    if (!ENGINE_set_RSA(e, &mecs)	) {
      printf("ENGINE_init_function failed\n");
      return 0;
    }


	//		!ENGINE_set_cmd_defns(e, pkcs11_cmd_defns) ||



	return 1;
}

static int bind(ENGINE * e, const char *id)
{
	/*
	if (id && (strcmp(id, engine_id) != 0)) {
		fprintf(stderr, "bad engine id\n");
		return 0;
	}
	*/
	if (!bind_helper(e)) {
		fprintf(stderr, "bind failed\n");
		return 0;
	}
	return 1;
}


IMPLEMENT_DYNAMIC_BIND_FN(bind)
IMPLEMENT_DYNAMIC_CHECK_FN()

