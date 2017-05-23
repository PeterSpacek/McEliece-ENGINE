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

//list of control commands
#define CMD_PARA	ENGINE_CMD_BASE
#define CMD_DIR	ENGINE_CMD_BASE+1


static int bpmecs_destroy(ENGINE * e);
int bpmecs_control_func(ENGINE *e, int cmd, long i, void *p, void (*f) (void));

//engine ID
static const char *engine_id ="bpmecs";
//engine name
static const char *engine_name ="bitpuch mceliece engine";
//structure for engine to know which function should use for encryption and decryption
static RSA_METHOD bpmecs =
{
  "McEliece",
  bpmecs_encrypt,
  NULL,
  NULL,
  bpmecs_decrypt,
  NULL,
  NULL,
  NULL,
  NULL,
  0,
  NULL,
  NULL,
  NULL
};

//control commands initialization
static const ENGINE_CMD_DEFN bpmecs_cmds[] = {
{CMD_PARA,
"KEYGEN",
"Type A or B for specify McEliece key parameters. Key generation will start right after.",
ENGINE_CMD_FLAG_STRING},
{CMD_DIR,
"DIR",
"You can specify output directory for public and private keys",
ENGINE_CMD_FLAG_STRING},
{0, NULL, NULL, 0}
};

//mathes control command and its function
int bpmecs_control_func(ENGINE *e, int cmd, long i, void *p, void (*f) (void)){
		(void)i;
		(void)f;
		switch (cmd) {
		case CMD_DIR:
			return bpmecs_set_key_DIR((const char *)p);
			break;
		case CMD_PARA:
			return bpmecs_keygen_ctrl((const char *)p);
			break;
		default:
			break;
		}
		return 1;
}

//engine destructor
static int bpmecs_destroy(ENGINE * e)
{
	(void)e;
	return 1;
}

//basic engine setting
static int bind_helper(ENGINE * e)
{
	//way to tell engine what is the its ID
	if (!ENGINE_set_id(e, engine_id)) {
      fprintf(stderr, "ENGINE_set_id failed\n");
      return 0;
    }
	//way to tell engine what is the its name
	if (!ENGINE_set_name(e, engine_name)) {
      fprintf(stderr, "ENGINE_set_name failed\n");
      return 0;
    }
	//way to tell engine what initialization function should use
	if (!ENGINE_set_init_function(e, bpmecs_init) ) {
      fprintf(stderr, "ENGINE_set_init_function failed\n");
      return 0;
    }
	//way to tell engine what destructor should be using
	if (!ENGINE_set_destroy_function(e, bpmecs_destroy) ) {
      fprintf(stderr, "ENGINE_set_destroy_function failed\n");
      return 0;
    }
	//way to tell engine what finish function should use
	if (!ENGINE_set_finish_function(e, bpmecs_finish) ) {
      fprintf(stderr, "ENGINE_set_finish_function failed\n");
      return 0;
    }
	//way to tell engine the control commands
	if (!ENGINE_set_cmd_defns(e, bpmecs_cmds)) {
		fprintf(stderr, "ENGINE_set_cmd_defns failed\n");
		return 0;
	}
	//way to tell engine what function for processing control command should use
    if (!ENGINE_set_ctrl_function(e, bpmecs_control_func)) {
      fprintf(stderr,"ENGINE_ctrl_function failed\n");
      return 0;
    }
    //way to tell engine how to load private key
    if (!ENGINE_set_load_privkey_function(e, bpmecs_load_key)) {
      fprintf(stderr,"ENGINE_set_load_privkey_function failed \n");
      return 0;
    }
    //way to tell engine how to load public key
    if (!ENGINE_set_load_pubkey_function(e, bpmecs_load_key)) {
      fprintf(stderr,"ENGINE_set_load_pubkey_function failed \n");
      return 0;
    }
    //way to tell engine that it will serve as public key system
    if (!ENGINE_set_RSA(e, &bpmecs)	) {
      printf("ENGINE_init_function failed\n");
      return 0;
    }

	return 1;
}

//function that connect openssl and engine
static int bind(ENGINE * e, const char *id)
{

	if (!bind_helper(e)) {
		fprintf(stderr, "bind failed\n");
		return 0;
	}
	return 1;
}


IMPLEMENT_DYNAMIC_BIND_FN(bind)
IMPLEMENT_DYNAMIC_CHECK_FN()

