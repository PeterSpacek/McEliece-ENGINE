/*
 * Copyright (c) 2017 Peter Spacek
 * Copyright (c) 2017 Pavol Zajac
 * Copyright (c) 2017 FEI STU BA
 */

#ifndef _ENGINE_BPMECS_H
#define _ENGINE_BPMECS_H

#ifndef _WIN32
#include <openssl/opensslconf.h>
#endif

#include <stdio.h>
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/objects.h>
#include <openssl/engine.h>


int bpmecs_finish(ENGINE * engine);

int bpmecs_init(ENGINE * engine);

int bpmecs_encrypt(int len, const unsigned char *from, unsigned char *to, RSA *rsa, int padding);

int bpmecs_decrypt(int len, const unsigned char *from, unsigned char *to, RSA *rsa, int padding);


int bpmecs_keygen(RSA *rsa, int bits,  BIGNUM * e,BN_GENCB *cb );

EVP_PKEY *bpmecs_load_key(ENGINE * e, const char *s_key_id,	UI_METHOD * ui_method, void *callback_data);

#endif

