/*
 * Copyright (c) 2017 Peter Spacek
 * Copyright (c) 2017 Pavol Zajac
 * Copyright (c) 2017 FEI STU BA
 */

#ifndef _ENGINE_BPMECS_H
#define _ENGINE_BPMECS_H

#ifndef _WIN32
#include "config.h"
#endif

#include <stdio.h>
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/objects.h>
#include <openssl/engine.h>


int bpmecs_finish(ENGINE * engine);

int bpmecs_init(ENGINE * engine);

int bpmecs_encrypt(EVP_PKEY_CTX *pctx, unsigned char *to, size_t *outlen, const unsigned char *from, size_t inlen);

int bpmecs_decrypt(EVP_PKEY_CTX *pctx, unsigned char *to, size_t *outlen, const unsigned char *from, size_t inlen);

EVP_PKEY *bpmecs_load_public_key(ENGINE * e, const char *s_key_id,	UI_METHOD * ui_method, void *callback_data);

EVP_PKEY  *bpmecs_load_private_key(ENGINE * e, const char *s_key_id,	UI_METHOD * ui_method, void *callback_data);

#endif

