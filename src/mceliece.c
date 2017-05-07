/*
 * Copyright (c) 2017 Peter Spacek
 * Copyright (c) 2017 Pavol Zajac
 * Copyright (c) 2017 FEI STU BA
 */

#include "engine_pkcs11.h"
#include <stdio.h>
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/objects.h>
#include <openssl/engine.h>
#include <libp11.h>

#include <bitpunch/bitpunch.h>
#include <bitpunch/tools.h>

#include <bitpunch/asn1/asn1.h>
#include "libtasn1.h"
#include <bitpunch/math/bigint.h>
#include <bitpunch/math/uni.h>

#ifdef _WIN32
#define strncasecmp strnicmp
#endif

BPU_T_Mecs_Ctx *ctx;


int bpmecs_finish(ENGINE * engine)
{
	(void)engine;

    BPU_mecsFreeCtx(&ctx);
	//TODO free everything

	return 1;
}

int bpmecs_init(ENGINE * engine)
{
	(void)engine;
	int rc;
	ctx=NULL;

	char* prikey= "prikey.der";
	char* pubkey= "pubkey.der";

	rc = BPU_asn1LoadKeyPair(&ctx, prikey, pubkey);

    if (rc) {
        asn1_perror(rc);
    }

	return 1;
}


static int char2gf2Vec(const unsigned char *from, int w, BPU_T_GF2_Vector *to){
	if ((from==NULL)||(to==NULL))
		return -1;
	int i,j;
    for(i = 0; i < w; i++) {
       for(j = 0; j<8; j++){
    	  BPU_gf2VecSetBit(to, (8*i)+(j),  ((*(from+i) >> j) & 0x01));
       }
    }
    return 0;
}

static int gf2Vec2char(BPU_T_GF2_Vector *fromm, int w, unsigned char  *to){
	if ((from==NULL)||(to==NULL))
		return -1;
    int i,j;
    char temp;
    for(i = 0; i < w; i++) {
    	temp=0;
    	for(j = 0; j<8; j++){
    	   	temp|= BPU_gf2VecGetBit(fromm, (8*i)+j)<<j;
    	}
    	to[i]=temp;
    }

    return 0;
}

int bpmecs_encrypt(EVP_PKEY_CTX *pctx, unsigned char *to, size_t *outlen, const unsigned char *from, size_t inlen){

    BPU_T_GF2_Vector *ct=NULL, *pt=NULL;

    // prepare plain text, allocate memory and init plaintext
    if (BPU_gf2VecMalloc(&pt, ctx->pt_len)) {
        BPU_printError("PT initialisation error");
        BPU_gf2VecFree(&pt);
        return -1;
    }

    if(char2gf2Vec(from,inlen,pt)==-1){
        fprintf(stderr, "char2gf2Vec function error\n");
        BPU_gf2VecFree(&pt);
        return -1;
    }

    // alocate cipher text vector
    if (BPU_gf2VecMalloc(&ct, ctx->ct_len)) {
        BPU_printError("CT vector allocation error");
        BPU_gf2VecFree(&pt);
        BPU_gf2VecFree(&ct);
        return -1;
    }

    // BPU_encrypt plain text
    if (BPU_mecsEncrypt(ct, pt, ctx)) {
        BPU_printError("Encryption error");
        BPU_gf2VecFree(&ct);
        BPU_gf2VecFree(&pt);
        return 1;
    }

    *outlen=ctx->ct_len/8;

    if( gf2Vec2char(ct,ctx->ct_len,to)==-1){
        fprintf(stderr, "gf2Vec2char function error\n");
        BPU_gf2VecFree(&ct);
        BPU_gf2VecFree(&pt);
        return -1;
    }

    BPU_gf2VecFree(&ct);
    BPU_gf2VecFree(&pt);
	return *outlen;
}


int bpmecs_decrypt(EVP_PKEY_CTX * pctx, unsigned char *to, size_t *outlen, const unsigned char *from, size_t inlen){

    BPU_T_GF2_Vector *ct=NULL, *pt=NULL;

    // prepare cipher text, allocate memory and init ciphertext
    if (BPU_gf2VecMalloc(&ct, ctx->ct_len)) {
        BPU_printError("CT initialisation error");
        BPU_gf2VecFree(&ct);
        return 1;
    }

    if(char2gf2Vec(from,inlen,ct)==-1){
       fprintf(stderr, "char2gf2Vec function error\n");
       BPU_gf2VecFree(&ct);
       return -1;
    }

    // alocate cipher text vector
    if (BPU_gf2VecMalloc(&pt, ctx->pt_len)) {
        BPU_printError("PT vector allocation error");
        BPU_gf2VecFree(&pt);
        BPU_gf2VecFree(&ct);
        return 1;
    }

    // decrypt cipher text
    if (BPU_mecsDecrypt(pt, ct, ctx)) {
    	BPU_printError("Decryption error");
		BPU_gf2VecFree(&ct);
		BPU_gf2VecFree(&pt);
		return 1;
	}

    *outlen=ctx->pt_len/8;

    if( gf2Vec2char(pt,ctx->pt_len,to)==-1){
        fprintf(stderr, "gf2Vec2char function error\n");
        BPU_gf2VecFree(&ct);
        BPU_gf2VecFree(&pt);
        return -1;
    }

    BPU_gf2VecFree(&ct);
    BPU_gf2VecFree(&pt);

	return *outlen;
}


/*
EVP_PKEY *pkcs11_load_public_key(ENGINE * e, const char *s_key_id,
		UI_METHOD * ui_method, void *callback_data)
{
	EVP_PKEY *pk;

	pk = pkcs11_load_key(e, s_key_id, ui_method, callback_data, 0);
	if (pk == NULL) {
		fprintf(stderr, "PKCS11_load_public_key returned NULL\n");
		return NULL;
	}
	return pk;
}
*/
/*

EVP_PKEY *pkcs11_load_private_key(ENGINE * e, const char *s_key_id,
		UI_METHOD * ui_method, void *callback_data)
{
	EVP_PKEY *pk;

	pk = pkcs11_load_key(e, s_key_id, ui_method, callback_data, 1);
	if (pk == NULL) {
		fprintf(stderr, "PKCS11_get_private_key returned NULL\n");
		return NULL;
	}
	return pk;
}
*/

