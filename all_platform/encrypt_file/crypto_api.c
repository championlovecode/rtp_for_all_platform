#include <pjlib.h>
#include <pjlib-util.h>
#include <pjmedia.h>
#include <pjmedia-codec.h>
#include <pjmedia/transport_srtp.h>
#include <stdlib.h>	/* atoi() */
#include <stdio.h>

#include "crypto_module.h"

#ifdef _WIN32
extern "C"{
#include "openssl/applink.c"
};
#endif


static AES_KEY_HANDLE_T g_key_handle_t = {0};

typedef struct META_DATA_INFO_s
{
    int len;
    void *addr;
}META_DATA_INFO_T;


extern void printfkey(char* temp,int len);


void CRYPTO_AES_encrypt_rtp(META_DATA_INFO_T *text_t, META_DATA_INFO_T *cipher_t)
{
	printf("\n CRYPTO_AES_encrypt_test come in \n");


    
    printf("\n  test len =%d ",text_t->len);

    printfkey(text_t->addr,text_t->len);

	if (CRYPTO_AES_encrypt(text_t->addr,cipher_t->addr, text_t->len, &g_key_handle_t))
	{
		printf("CRYPTO_AES_encrypt Error\n");		 
	}

    cipher_t->len = text_t->len;

    printf("\n  cipher len =%d ",text_t->len);

    printfkey(cipher_t->addr, text_t->len);

    printf("\n CRYPTO_AES_encrypt_test come out \n");
#if 0
    printf("--------- For test Decrypt ----------\n");

    unsigned char tmp_text[161] = {0};
    memset(tmp_text, 0, sizeof(tmp_text));

    if (CRYPTO_AES_decrypt(cipher_t->addr, tmp_text, text_t->len, &g_key_handle_t))
    {
        printf("CRYPTO_AES_encrypt Error\n");
    }
    printfkey((char*)&tmp_text[0], text_t->len);

    printf("--------- End test Decrypt ----------\n");
#endif 

}

void CRYPTO_AES_decrypt_rtp(META_DATA_INFO_T *cipher_t, META_DATA_INFO_T *text_t)
{
//    printf("\n CRYPTO_AES_decrypt_rtp come in \n");

//    printf("cipher_t.len = %d",cipher_t->len);
//    printfkey(cipher_t->addr,cipher_t->len);

    if (CRYPTO_AES_decrypt(cipher_t->addr, text_t->addr, cipher_t->len, &g_key_handle_t))
    {
        printf("CRYPTO_AES_encrypt Error\n");
    }

    text_t->len = cipher_t->len;

//    printf("\n CRYPTO_AES_decrypt_rtp come out \n");
}


void CRYPTO_AES_encrypt_init(void)
{	 
	CRYPTO_AES_encrypt_decrypt_register((PTR_ENCRYPT)CRYPTO_AES_encrypt_rtp,(PTR_ENCRYPT)CRYPTO_AES_decrypt_rtp);

//    printf("\n CRYPTO_AES_encrypt_init in \n");

    g_key_handle_t.feedback_mode = AES_128_OFB;
    strcpy((char*)&g_key_handle_t.IV[0], AES_IV);

    if (CRYPTO_AES_init(&g_key_handle_t))
	{
		printf("CRYPTO_AES_init ERROR: %s\n", CRYPTO_err_string());
	}
//	printf("\n CRYPTO_AES_encrypt_init out  \n");
}

void sendcallaeskey(char *tempkey)
{
    printf("\n tempkey = %s \n", tempkey);
    memset(&g_key_handle_t, 0, sizeof(AES_KEY_HANDLE_T));
    strncpy(g_key_handle_t.hex_key_str, tempkey, strlen(tempkey));
}

