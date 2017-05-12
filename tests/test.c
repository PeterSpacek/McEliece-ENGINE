#include <stdlib.h>
#include <time.h>
#include <sys/time.h>
#include <openssl/engine.h>
#include <stdio.h>
#include <string.h>

int main(int argc, const char* argv[] ) {
    OpenSSL_add_all_algorithms();

    ERR_load_crypto_strings();

    ENGINE_load_dynamic();
    ENGINE *engine = ENGINE_by_id("pwd/bpmecs.so");

    if( engine == NULL )
    {
        printf("Could not Load Engine!\n");
        exit(1);
    }
    printf("Engine successfully loaded\n");

    int init_res = ENGINE_init(engine);
    printf("Engine name: %s init result : %d \n",ENGINE_get_name(engine), init_res);
    
    if(!ENGINE_set_default_RSA(engine))
        abort();
    return 0;
}
