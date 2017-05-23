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


// ctx is BitPunch McEliece key structure
BPU_T_Mecs_Ctx *ctx;
// path to folder with keys
const char *bpmecs_key_DIR;

static int char2gf2Vec(const unsigned char *from, int w, BPU_T_GF2_Vector *to);
static int gf2Vec2char(BPU_T_GF2_Vector *from, int w, unsigned char  *to);
static int fileExists (char *filename);

//test if the file exists
static int fileExists (char *filename){
	FILE *file;
	if((file=fopen(filename,"r"))!=NULL){
		fclose(file);
		return 1;
	}
	else return 0;
}


//reformating data from unsigned char * to BPU_T_GF2_Vector
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
//reformating data from BPU_T_GF2_Vector to unsigned char *
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
//engine finish function
int bpmecs_finish(ENGINE * engine)
{
	(void)engine;
    BPU_mecsFreeCtx(&ctx);
	return 1;
}

//engine initialization function
int bpmecs_init(ENGINE * engine)
{
	(void)engine;
	return 1;
}

// engine encryption function
int bpmecs_encrypt(int inlen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding){
	  int outlen=-1;
      BPU_T_GF2_Vector *ct, *pt;

	  // prepare plain text, allocate memory and init plaintext
	  if (BPU_gf2VecMalloc(&pt, ctx->pt_len)) {
	        BPU_printError("PT initialisation error");
	        BPU_gf2VecFree(&pt);
	        return 0;
	  }
	  //add length information
	  unsigned char * copy;
	  copy=malloc(inlen+2);
	  strncpy(copy+2, from,inlen);
	  copy[0]=(unsigned char)(inlen)&0xff;
	  copy[1]=(unsigned char)(inlen>>8)&0xff;

	  //reformat data
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
	  // to=(unsigned char*)realloc(to,outlen);
	  //reformat output data
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

//engine decrypion function
int bpmecs_decrypt(int inlen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding){
	int outlen=-1;
    BPU_T_GF2_Vector *ct=NULL, *pt=NULL;

    // prepare cipher text, allocate memory and init ciphertext
    if (BPU_gf2VecMalloc(&ct, ctx->ct_len)) {
        BPU_printError("CT initialisation error");
        BPU_gf2VecFree(&ct);
        return 0;
    }
    //reformat imput data
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
	unsigned char * copy;
	copy=malloc(outlen);

	//reformat out data
    if( gf2Vec2char(pt,outlen,copy)==-1){
        fprintf(stderr, "gf2Vec2char function error\n");
        BPU_gf2VecFree(&ct);
        BPU_gf2VecFree(&pt);
        return 0;
    }
    //extract length information
    outlen=(int)copy[0];
    outlen+=((int)copy[1])<<8;
	strncpy(to, copy+2,outlen);
	free(copy);

    BPU_gf2VecFree(&ct);
    BPU_gf2VecFree(&pt);
	return outlen;
}

// engine keygen function
int bpmecs_keygen_ctrl(const char *param){
	if (param == NULL) {
		errno = EINVAL;
		return 0;
	}
	if (bpmecs_key_DIR == NULL) {
		bpmecs_key_DIR="KEY";
		return 0;
	}
	int rc = 0;
	BPU_T_UN_Mecs_Params params;

	//goppa codes initialization
	switch (toupper(param[0])){
	case 'A':
		if (BPU_mecsInitParamsGoppa(&params, 11, 50, 0 )) {
			return 0;
		}
		break;
	case 'B':
		if (BPU_mecsInitParamsGoppa(&params, 13, 121, 0x2129)) {
			return 0;
		}
		break;
	default:
		return 0;
	}
	if (BPU_mecsInitCtx(&ctx, &params, BPU_EN_MECS_BASIC_GOPPA)) {
	    return 0;
	}

	// key pair generation
	if (BPU_mecsGenKeyPair(ctx)) {
	    BPU_printError("Key generation error");
	    return 0;
	}

	//export asn.1 keys
	char* prikey=malloc(strlen(bpmecs_key_DIR)+1+11);
	strcpy(prikey,bpmecs_key_DIR);
	strcat(prikey,"/prikey.der");

	char* pubkey=malloc(strlen(bpmecs_key_DIR)+1+11);
	strcpy(pubkey,bpmecs_key_DIR);
	strcat(pubkey,"/pubkey.der");

	fprintf(stderr,prikey);
	fprintf(stderr,pubkey);
	rc = BPU_asn1SaveKeyPair(ctx, prikey, pubkey);
	if (rc) {
	    asn1_perror(rc);
	    return 0;
	}

	BPU_mecsFreeParamsGoppa(&params);
    fprintf(stderr,"Success \n");
	return 1;
}

//control function for setting key directory
int bpmecs_set_key_DIR(const char *dir){
	bpmecs_key_DIR=dir;
	return 1;
}

//engine key loading function
EVP_PKEY * bpmecs_load_key(ENGINE *eng, const char *key_id,UI_METHOD *ui_method, void *callback_data){
	(void)eng;
	int rc;
	const char * key;

	//actual key loading
	char* prikey=malloc(strlen(key_id)+1+11);
	strcpy(prikey,key_id);
	strcat(prikey,"/prikey.der");

	char* pubkey=malloc(strlen(key_id)+1+11);
	strcpy(pubkey,key_id);
	strcat(pubkey,"/pubkey.der");

	if(fileExists(prikey)){
		if(fileExists(pubkey)){
	        rc = BPU_asn1LoadKeyPair(&ctx, prikey, pubkey);
	        if (rc)
	        	asn1_perror(rc);
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

	//fake key loading needs to be done to tell engine what size of RSA should be used
	EVP_PKEY *privkey;
	BIO *keybio ;
	/*
	char keys[]="-----BEGIN PUBLIC KEY-----\n"\
	"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAy8Dbv8prpJ/0kKhlGeJY\n"\
	"ozo2t60EG8L0561g13R29LvMR5hyvGZlGJpmn65+A4xHXInJYiPuKzrKUnApeLZ+\n"\
	"vw1HocOAZtWK0z3r26uA8kQYOKX9Qt/DbCdvsF9wF8gRK0ptx9M6R13NvBxvVQAp\n"\
	"fc9jB9nTzphOgM4JiEYvlV8FLhg9yZovMYd6Wwf3aoXK891VQxTr/kQYoq1Yp+68\n"\
	"i6T4nNq7NWC+UNVjQHxNQMQMzU6lWCX8zyg3yH88OAQkUXIXKfQ+NkvYQ1cxaMoV\n"\
	"PpY72+eVthKzpMeyHkBn7ciumk5qgLTEJAfWZpe4f4eFZj/Rc8Y8Jj2IS5kVPjUy\n"\
	"wQIDAQAB\n"\
	"-----END PUBLIC KEY-----\n";
	*/
	char keys[]="-----BEGIN RSA PRIVATE KEY-----\n"\
	"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\n"\
	"-----END RSA PRIVATE KEY-----\n";
	keybio = BIO_new_mem_buf(keys, -1);
	privkey = EVP_PKEY_new();
	//PEM_read_bio_PUBKEY( keybio, &privkey, NULL, NULL);
	PEM_read_bio_PrivateKey( keybio, &privkey, NULL, NULL);
	return privkey;

}

