/*
 * Author: Ken Chow
 * Email : kenchow@xpphone.net
 * Date  : 2016-4-11
 * This module offered a few interfaces for implementing RSA and AES in FIPS openssl mode.
 */
#ifndef _CRYPTO_MODULE_H_
#define _CRYPTO_MODULE_H_

#ifdef  __cplusplus
extern "C" {
#endif

#define NON_FIPS

/* define for AES */
#define AES_IV "xpphoneaesivweng"
/* End of AES */

#define MAX_ERR_NO 		        (~0)
#define ERR_PARAMETERS_NULL   (MAX_ERR_NO-1)
#define ERR_LENGTH_INVALID    (MAX_ERR_NO-2)
#define ERR_BITS_INVALID      (MAX_ERR_NO-3)
#define ERR_PADDING_PARAMETER (MAX_ERR_NO-4)
#define ERR_INIT_KEY					(MAX_ERR_NO-5)

typedef enum RSA_PADDING_e {
	PKCS1_PADDING = 1,
	SSLV23_PADDING = 2,
	NO_PADDING = 3,
	PKCS1_OAEP_PADDING = 4,
	PADDING_BUTT
} RSA_PADDING_E;

typedef enum AES_FEEDBACK_MODE_e {
	AES_128_ECB = 1,
	AES_128_OFB,
	AES_128_CTR,
	AES_128_XTS,
	AES_256_ECB,
	AES_256_OFB,
	AES_256_CTR,
	AES_256_XTS,
	FEEDBACK_MODE_BUTT
} AES_FEEDBACK_MODE_E;

typedef struct RSA_KEY_HANDLE_s {
	int key_bits; // 1024, 2048, 3072 or 4096
	int padding; // see RSA_PADDING_E
	int public_key_len;
	unsigned char *public_key;
	void *rsa_pub; // actual type: RSA
	int private_key_len;
	unsigned char *private_key;
	unsigned char passphrase[1024];
	void *rsa_pri; // actual type: RSA
} RSA_KEY_HANDLE_T;

typedef struct AES_KEY_HANDLE_s {
	int key_bits; // 128, 192 or 256
	int feedback_mode; // see AES_FEEDBACK_MODE_E
	unsigned char IV[32];
	char hex_key_str[65];
	unsigned char key[32];
	void *ctx; // actual type: EVP_CIPHER_CTX
} AES_KEY_HANDLE_T;

unsigned char *CRYPTO_err_string();
int CRYPTO_err_clean();
unsigned char *CRYPTO_get_version();
int CRYPTO_set_fips_mode(int mode);
int CRYPTO_mode();

///////////////////////////////////////////////////////////////////////////////////
/*
 * input : key_bits
 * output: key_len, public_key, private_key
 */
int CRYPTO_RSA_keys_generate(RSA_KEY_HANDLE_T *key_t);

/*
 * input : pub_key_len public_key or/and pub_key_len public_key
 * output: rsa_pub or rsa_pri
 */
int CRYPTO_RSA_init(RSA_KEY_HANDLE_T *key_t);

/*
 * input: key_t
 */
int CRYPTO_RSA_release(RSA_KEY_HANDLE_T *key_t);

/*
 * input : text, key_t
 * output: cipher
 * return: error: -1, success: encrypt length
 */
int CRYPTO_RSA_public_key_encrypt(const unsigned char *text,
		unsigned char *cipher, RSA_KEY_HANDLE_T *key_t);

/*
 * input : cipher, key_t
 * output: text
 * return: error: -1, success: decrypt length
 */
int CRYPTO_RSA_private_key_decrypt(const unsigned char *cipher,
		unsigned char *text, RSA_KEY_HANDLE_T *key_t);
////////////////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////////////////
/*
 * input : key_bits
 * output: hex_key_str, key
 */
int CRYPTO_AES_key_generate(AES_KEY_HANDLE_T *key_t);

/*
 * input : key, key_len
 * output: key_handle_t
 */
int CRYPTO_AES_init(AES_KEY_HANDLE_T *key_t);

/*
 * input : key_handle_t
 */
int CRYPTO_AES_release(AES_KEY_HANDLE_T *key_t);

/*
 * input : text_t, key
 * output: cipher_t
 * return: error: -1, success: 0
 */
int CRYPTO_AES_encrypt(const unsigned char *text, unsigned char *cipher,
		unsigned int len, AES_KEY_HANDLE_T *key_t);

/*
 * input : cipher_t, key
 * output: text_t
 * return: error: -1, success: 0
 */
int CRYPTO_AES_decrypt(const unsigned char *cipher, unsigned char *text,
		unsigned int len, AES_KEY_HANDLE_T *key_t);
////////////////////////////////////////////////////////////////////////////////////

/*
 * input : input, input_len
 * output: *output
 * return: error: -1, >0: output length
 */
int CRYPTO_to_base64(const unsigned char *input, int input_len, char **output);

/*
 * input : input, input_len
 * output: *output
 * return: error: -1, >0: output length
 */
int CRYPTO_from_base64(const unsigned char *input, int input_len,
		char **output);

#ifdef  __cplusplus
}
#endif

#endif /* _CRYPTO_MODULE_H_ */

