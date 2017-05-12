/*
 * Copyright (c) 2017 Peter Spacek
 * Copyright (c) 2017 Pavol Zajac
 * Copyright (c) 2017 FEI STU BA
 */

#include "mceliece.h"
#include <stdio.h>
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/objects.h>
#include <openssl/engine.h>

#include <bitpunch/bitpunch.h>
#include <bitpunch/tools.h>

#include <bitpunch/asn1/asn1.h>
#include <bitpunch/math/bigint.h>
#include <bitpunch/math/uni.h>

#ifdef _WIN32
#define strncasecmp strnicmp
#endif

BPU_T_Mecs_Ctx *ctx;

static int char2gf2Vec(const unsigned char *from, int w, BPU_T_GF2_Vector *to);
static int gf2Vec2char(BPU_T_GF2_Vector *from, int w, unsigned char  *to);
static int fileExists (char *filename);


int bpmecs_finish(ENGINE * engine)
{
	(void)engine;

    BPU_mecsFreeCtx(&ctx);
	//TODO free everything

	return 1;
}
static int fileExists (char *filename){
	FILE *file;
	if((file=fopen(filename,"r"))!=NULL){
		fclose(file);
		return 1;
	}
	else return 0;
}

int bpmecs_init(ENGINE * engine)
{
	(void)engine;
	int rc;
	ctx=NULL;


	char* prikey= "prikey.der";
	char* pubkey= "pubkey.der";

	    if(fileExists(prikey)){
	    	if(fileExists(pubkey)){
	        	rc = BPU_asn1LoadKeyPair(&ctx, prikey, pubkey);
	          	if (rc) asn1_perror(rc);
	            }
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

static int gf2Vec2char(BPU_T_GF2_Vector *from, int w, unsigned char  *to){
	if ((from==NULL)||(to==NULL))
		return -1;
    int i,j;
    char temp;
    for(i = 0; i < w; i++) {
    	temp=0;
    	for(j = 0; j<8; j++){
    	   	temp|= BPU_gf2VecGetBit(from, (8*i)+j)<<j;
    	}
    	to[i]=temp;
    }

    return 0;
}

/* encrypt */
int bpmecs_encrypt(int inlen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding){

	  int outlen=-1;
      BPU_T_GF2_Vector *ct, *pt;

	  // prepare plain text, allocate memory and init plaintext
	  if (BPU_gf2VecMalloc(&pt, ctx->pt_len)) {
	        BPU_printError("PT initialisation error");
	        BPU_gf2VecFree(&pt);
	        return 0;
	  }
	  unsigned char * copy;
	  copy=malloc(inlen+1);
	  strcpy(copy+1, from);
	  copy[0]=inlen;

	  if(char2gf2Vec(copy,inlen+1,pt)==-1){
	        fprintf(stderr, "char2gf2Vec function error\n");
	        BPU_gf2VecFree(&pt);
	        return 0;
	  }
	  free(copy);
	  // alocate cipher text vector
	  if (BPU_gf2VecMalloc(&ct, ctx->ct_len)) {
	        BPU_printError("CT vector allocation error");
	        BPU_gf2VecFree(&pt);
	        BPU_gf2VecFree(&ct);
	        return 0;
	  }


	  // BPU_encrypt plain text
	  if (BPU_mecsEncrypt(ct, pt, ctx)) {
	        BPU_printError("Encryption error");
	        BPU_gf2VecFree(&ct);
	        BPU_gf2VecFree(&pt);
	        return 0;
	  }

	  outlen=ctx->ct_len/8;

	//  to=(unsigned char*)malloc(outlen);

	  if( gf2Vec2char(ct,outlen,to)==-1){
	        fprintf(stderr, "gf2Vec2char function error\n");
	        BPU_gf2VecFree(&ct);
	        BPU_gf2VecFree(&pt);
	        return 0;
	  }

      BPU_gf2VecFree(&ct);
      BPU_gf2VecFree(&pt);

      return outlen;
}

/* decrypt */
int bpmecs_decrypt(int inlen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding){
	int outlen=-1;

    BPU_T_GF2_Vector *ct=NULL, *pt=NULL;

    // prepare cipher text, allocate memory and init ciphertext
    if (BPU_gf2VecMalloc(&ct, ctx->ct_len)) {
        BPU_printError("CT initialisation error");
        BPU_gf2VecFree(&ct);
        return 0;
    }

    if(char2gf2Vec(from,inlen,ct)==-1){
       fprintf(stderr, "char2gf2Vec function error\n");
       BPU_gf2VecFree(&ct);
       return 0;
    }

    // alocate plain text vector
    if (BPU_gf2VecMalloc(&pt, ctx->pt_len)) {
        BPU_printError("PT vector allocation error");
        BPU_gf2VecFree(&pt);
        BPU_gf2VecFree(&ct);
        return 0;
    }

    // decrypt cipher text
    if (BPU_mecsDecrypt(pt, ct, ctx)) {
    	BPU_printError("Decryption error");
		BPU_gf2VecFree(&ct);
		BPU_gf2VecFree(&pt);
		return 0;
	}

    outlen=ctx->pt_len/8;

	//to=(unsigned char*)malloc(outlen);
	unsigned char * copy;
	copy=malloc(outlen);

    if( gf2Vec2char(pt,outlen,copy)==-1){
        fprintf(stderr, "gf2Vec2char function error\n");
        BPU_gf2VecFree(&ct);
        BPU_gf2VecFree(&pt);
        return 0;
    }
	strcpy(to, copy+1);
	outlen=copy[0];
	free(copy);
    BPU_gf2VecFree(&ct);
    BPU_gf2VecFree(&pt);

	return outlen;
}

int bpmecs_keygen(RSA *rsa, int bits,  BIGNUM * e,BN_GENCB *cb ){
	int rc = 0;
	BPU_T_UN_Mecs_Params params;

	// mce initialisation t = 50, m = 11
	if (BPU_mecsInitParamsGoppa(&params,13 , 119, 0x2129)) {
	    return 0;
	}

	if (BPU_mecsInitCtx(&ctx, &params, BPU_EN_MECS_BASIC_GOPPA)) {
  //if (BPU_mecsInitCtx(&ctx, 11, 50, BPU_EN_MECS_CCA2_POINTCHEVAL_GOPPA)) {
	    return 0;
	}

	// key pair generation
	if (BPU_mecsGenKeyPair(ctx)) {
	    BPU_printError("Key generation error");
	    return 0;
	}

	rc = BPU_asn1SaveKeyPair(ctx, "prikey.der", "pubkey.der");
	if (rc) {
	    asn1_perror(rc);
	    return 0;
	}

	BPU_mecsFreeParamsGoppa(&params);

    return 1;
}

EVP_PKEY * bpmecs_load_key(ENGINE *eng, const char *key_id,UI_METHOD *ui_method, void *callback_data){
	(void)eng;
	int rc;
	const char * key;

	//actual key loading
	char* prikey=malloc(sizeof(key_id)+1+11);
	strcpy(prikey,key_id);
	strcat(prikey,"/prikey.der");

	char* pubkey=malloc(sizeof(key_id)+1+11);
	strcpy(pubkey,key_id);
	strcat(pubkey,"/pubkey.der");

	if(fileExists(prikey)){
		if(fileExists(pubkey)){
	        rc = BPU_asn1LoadKeyPair(&ctx, prikey, pubkey);
	        if (rc) asn1_perror(rc);
	        }
		else {
	        fprintf(stderr, "cannot load %s\n",pubkey);
			return NULL;
		}
	}
	else {
        fprintf(stderr, "cannot load %s\n",prikey);
		return NULL;
	}

	//fake key loading needs to be done to be able to use loading function
	EVP_PKEY *privkey;
	BIO *keybio ;
	char keys[]="-----BEGIN PUBLIC KEY-----\n"\
	"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAy8Dbv8prpJ/0kKhlGeJY\n"\
	"ozo2t60EG8L0561g13R29LvMR5hyvGZlGJpmn65+A4xHXInJYiPuKzrKUnApeLZ+\n"\
	"vw1HocOAZtWK0z3r26uA8kQYOKX9Qt/DbCdvsF9wF8gRK0ptx9M6R13NvBxvVQAp\n"\
	"fc9jB9nTzphOgM4JiEYvlV8FLhg9yZovMYd6Wwf3aoXK891VQxTr/kQYoq1Yp+68\n"\
	"i6T4nNq7NWC+UNVjQHxNQMQMzU6lWCX8zyg3yH88OAQkUXIXKfQ+NkvYQ1cxaMoV\n"\
	"PpY72+eVthKzpMeyHkBn7ciumk5qgLTEJAfWZpe4f4eFZj/Rc8Y8Jj2IS5kVPjUy\n"\
	"wQIDAQAB\n"\
	"-----END PUBLIC KEY-----\n";
	keybio = BIO_new_mem_buf(keys, -1);
	privkey = EVP_PKEY_new();
	PEM_read_bio_PUBKEY( keybio, &privkey, NULL, NULL);
	return privkey;

}

