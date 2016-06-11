#include <stdio.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
# include<openssl/e_os2.h>
# include<openssl/bio.h>
# include<openssl/ssl.h>

#include "crypto_module.h"

#ifndef NON_FIPS
#include <openssl/fips.h>
#include <openssl/fipssyms.h>
#endif

#define VERSION_STR 	"CryptoModule 0.9"

/* define for in NON-FIPS mode */
#ifdef NON_FIPS
#define FIPS_bn_new BN_new
#define FIPS_rsa_new  RSA_new
#define FIPS_rsa_generate_key_ex  RSA_generate_key_ex
#define FIPS_bn_free  BN_free
#define FIPS_rsa_free RSA_free
#define FIPS_rsa_size RSA_size
#define FIPS_rsa_public_encrypt RSA_public_encrypt
#define FIPS_rsa_private_decrypt  RSA_private_decrypt
#define FIPS_cipher_ctx_init  EVP_CIPHER_CTX_init
#define FIPS_cipher_ctx_cleanup EVP_CIPHER_CTX_cleanup
#define FIPS_cipherinit EVP_CipherInit
#define FIPS_cipher EVP_Cipher
#define FIPS_evp_aes_128_ecb EVP_aes_128_ecb
#define FIPS_evp_aes_128_ofb EVP_aes_128_ofb
#define FIPS_evp_aes_128_ctr EVP_aes_128_ctr
#define FIPS_evp_aes_128_xts EVP_aes_128_xts
#define FIPS_evp_aes_256_ecb EVP_aes_256_ecb
#define FIPS_evp_aes_256_ofb EVP_aes_256_ofb
#define FIPS_evp_aes_256_ctr EVP_aes_256_ctr
#define FIPS_evp_aes_256_xts EVP_aes_256_xts
#endif
/* end of define for FIPS mode */

/* define for RSA */
#define RSA_MIN_KEY_LEN 128
#define RSA_MAX_KEY_LEN 512
/* End of RSA */

unsigned long g_err_number = 0L;
char g_err_file[1024] = { 0 };
char g_err_func[1024] = { 0 };
unsigned int g_err_line = 0;

unsigned char *CRYPTO_err_string() {
	unsigned char buf[2048];
	memset(buf, 0, sizeof(buf));

	if (ERR_PARAMETERS_NULL == g_err_number) {
		sprintf(buf, "file(%s):func(%s):line(%d):reason(parameters invalid)", \
		g_err_file, g_err_func, g_err_line);
		return &buf[0];
	} else if (ERR_LENGTH_INVALID == g_err_number) {
		sprintf(buf, "file(%s):func(%s):line(%d):reason(length invalid)", \
		g_err_file, g_err_func, g_err_line);
		return &buf[0];
	} else if (ERR_BITS_INVALID == g_err_number) {
		sprintf(buf, "file(%s):func(%s):line(%d):reason(bits invalid)", \
		g_err_file, g_err_func, g_err_line);
		return &buf[0];
	} else if (ERR_PADDING_PARAMETER == g_err_number) {
		sprintf(buf, "file(%s):func(%s):line(%d):reason(rsa padding invalid)", \
		g_err_file, g_err_func, g_err_line);
		return &buf[0];
	} else if (ERR_INIT_KEY == g_err_number) {
		sprintf(buf, "file(%s):func(%s):line(%d):reason(rsa key init failed)", \
		g_err_file, g_err_func, g_err_line);
		return &buf[0];
	} else {
		sprintf(buf, "file(%s):func(%s):line(%d):reason[%s]", \
		g_err_file, g_err_func, g_err_line, ERR_error_string(g_err_number, NULL));
		return &buf[0];
	}

	return "UNKNOW ERROR!!!";
}

int CRYPTO_err_clean() {
	g_err_number = 0L;
	memset(g_err_file, 0, 1024);
	memset(g_err_func, 0, 1024);
	g_err_line = 0;
	return 0;
}

static void set_error_info(const char *file, const char *func, const int line,\
		const unsigned long err) {
	g_err_number = err;

	memset(g_err_file, 0, 1024);
	memcpy(g_err_file, file, 1024);

	memset(g_err_func, 0, 1024);
	memcpy(g_err_func, func, 1024);

	g_err_line = line;
}

unsigned char *CRYPTO_get_version() {
	return VERSION_STR;
}

int CRYPTO_set_fips_mode(int mode) {
#ifndef NON_FIPS
	if (1 != FIPS_mode_set(mode)) {
		set_error_info(__FILE__, __FUNCTION__, __LINE__, ERR_get_error());
		return -1;
	}
#endif
	return 0;
}

int CRYPTO_mode() {
#ifndef NON_FIPS
	return FIPS_mode();
#else
	return 0;
#endif
}

int CRYPTO_RAND_bytes(unsigned char *buf, int num) {
	return RAND_bytes(buf, num);
}

static int RSA_key_to_string(RSA *rsa, const EVP_CIPHER *enc, \
														const char *passphrase, int key_type, \
														unsigned char **key_str) {
	int length = -1;
	RSA *rsa_tmp = NULL;

	if (NULL == rsa) {
		set_error_info(__FILE__, __FUNCTION__, __LINE__, ERR_PARAMETERS_NULL);
		return -1;
	}

	BIO *out = BIO_new(BIO_s_mem());
	if (NULL == out) {
		set_error_info(__FILE__, __FUNCTION__, __LINE__, ERR_get_error());
		return -1;
	}

	// private key
	if (1 == key_type) {
		rsa_tmp = RSAPrivateKey_dup(rsa);
		EVP_PKEY *pkey = EVP_PKEY_new();
		EVP_PKEY_assign_RSA(pkey, rsa_tmp);
		PEM_write_bio_PKCS8PrivateKey(out, pkey, enc, NULL, 0, NULL, (void*)passphrase);
	} else {
		rsa_tmp = RSAPublicKey_dup(rsa);
		PEM_write_bio_RSA_PUBKEY(out, rsa_tmp);
	}

	if (NULL != rsa_tmp) {
		FIPS_rsa_free(rsa_tmp);
		rsa_tmp = NULL;
	}

	/* Flush the BIO to make sure it's all written. */
	(void) BIO_flush(out);
	(void) BIO_set_close(out, BIO_NOCLOSE);
	length = BIO_get_mem_data(out, key_str);
	if (*key_str == NULL) {
		BIO_free_all(out);
		set_error_info(__FILE__, __FUNCTION__, __LINE__, ERR_get_error());
		return -1;
	}

	if (NULL != out)
		BIO_free(out);

	return length;
}

static int RSA_key_to_rsa(RSA **rsa, int key_type, \
													const unsigned char *passphrase, \
													const unsigned char *key_str) {
	if ((NULL != *rsa) || (NULL == key_str)) {
		set_error_info(__FILE__, __FUNCTION__, __LINE__, ERR_PARAMETERS_NULL);
		return -1;
	}

	BIO *in = BIO_new_mem_buf((void*) key_str, -1);

	// private key
	if (1 == key_type) {
		*rsa = PEM_read_bio_RSAPrivateKey(in, NULL, NULL, \
			strlen(passphrase)==0?NULL:(void*)passphrase);
		if (NULL == *rsa) {
			set_error_info(__FILE__, __FUNCTION__, __LINE__, ERR_get_error());
			BIO_free_all(in);
			return -1;
		}
	} else // public key
	{
		*rsa = PEM_read_bio_RSA_PUBKEY(in, NULL, NULL, NULL);
		if (*rsa == NULL) {
			set_error_info(__FILE__, __FUNCTION__, __LINE__, ERR_get_error());
			BIO_free_all(in);
			return -1;
		}
	}

	if (NULL != in)
		BIO_free_all(in);

	return 0;
}

int CRYPTO_RSA_keys_generate(RSA_KEY_HANDLE_T *key_t) {
	RSA *rsa = NULL;
	BIGNUM *bne = NULL;
	int pub_key_len = -1;
	int pri_key_len = -1;

	/*
	 * 1. CA needs the key length more than 2048.
	 * 2. If the length too long may not suitable for cell phones.
	 * 4096 is a huge primer
	 */
	if (key_t->key_bits == 1024) {
	} else if (key_t->key_bits == 2048) {
	} else if (key_t->key_bits == 3072) {
	} else if (key_t->key_bits == 4096) {
	} else {
		set_error_info(__FILE__, __FUNCTION__, __LINE__, ERR_BITS_INVALID);
		return -1;
	}

	OpenSSL_add_all_algorithms();

	for (;;) {
		bne = FIPS_bn_new();
		if (1 != BN_set_word(bne, RSA_F4)) {
			set_error_info(__FILE__, __FUNCTION__, __LINE__, ERR_get_error());
			break;
		}

		rsa = FIPS_rsa_new();

		if (1 != FIPS_rsa_generate_key_ex(rsa, key_t->key_bits, bne, NULL)) {
			set_error_info(__FILE__, __FUNCTION__, __LINE__, ERR_get_error());
			break;
		}

		// get private key
		if (0 == strlen(key_t->passphrase))
		{
			key_t->private_key_len = RSA_key_to_string(rsa, NULL, NULL, 1, &key_t->private_key);
		}
		else
		{
			key_t->private_key_len = RSA_key_to_string(rsa, EVP_aes_128_cfb(), \
																		key_t->passphrase, 1, &key_t->private_key);
		}
		// get public key
		key_t->public_key_len = RSA_key_to_string(rsa, NULL, NULL, 0, &key_t->public_key);

		break;
	}

	if (NULL != bne)
		FIPS_bn_free(bne);

	if (NULL != rsa)
		FIPS_rsa_free(rsa);

	if (g_err_number || (-1 == key_t->private_key_len) || (-1 == key_t->public_key_len)){
		set_error_info(__FILE__, __FUNCTION__, __LINE__, ERR_PARAMETERS_NULL);
		return -1;
	}

	return 0;
}

int CRYPTO_RSA_init(RSA_KEY_HANDLE_T *key_t) {
	RSA *rsa_pub = NULL;
	RSA *rsa_pri = NULL;

	if (NULL == key_t) {
		set_error_info(__FILE__, __FUNCTION__, __LINE__, ERR_PARAMETERS_NULL);
		return -1;
	}

	if (0 >= key_t->padding) {
		set_error_info(__FILE__, __FUNCTION__, __LINE__, ERR_PADDING_PARAMETER);
		return -1;
	}

	OpenSSL_add_all_algorithms();

	// load private key
	if ((NULL != key_t->private_key) && (0 < strlen(key_t->private_key))) {
		if (RSA_key_to_rsa(&rsa_pri, 1, key_t->passphrase, key_t->private_key)) {
			FIPS_rsa_free(rsa_pri);
			set_error_info(__FILE__, __FUNCTION__, __LINE__, ERR_INIT_KEY);
			return -1;
		}
		key_t->rsa_pri = rsa_pri;
	}

	// load public key
	if ((NULL != key_t->public_key) && (0 < strlen(key_t->public_key))) {
		if (RSA_key_to_rsa(&rsa_pub, 0, NULL, key_t->public_key)) {
			FIPS_rsa_free(rsa_pub);
			set_error_info(__FILE__, __FUNCTION__, __LINE__, ERR_INIT_KEY);
			return -1;
		}
		key_t->rsa_pub = rsa_pub;
	}

	return 0;
}

int CRYPTO_RSA_release(RSA_KEY_HANDLE_T *key_t) {
	if (NULL == key_t) {
		set_error_info(__FILE__, __FUNCTION__, __LINE__, ERR_PARAMETERS_NULL);
		return -1;
	}
	if (key_t->rsa_pub) {
		FIPS_rsa_free(key_t->rsa_pub);
		key_t->rsa_pub = NULL;
	}
	if (key_t->rsa_pri) {
		FIPS_rsa_free(key_t->rsa_pri);
		key_t->rsa_pri = NULL;
	}
	if (key_t->private_key) {
		free(key_t->private_key);
		key_t->private_key = NULL;
	}
	if (key_t->public_key) {
		free(key_t->public_key);
		key_t->public_key = NULL;
	}

	memset((char*) key_t, 0, sizeof(RSA_KEY_HANDLE_T));
	return 0;
}

int CRYPTO_RSA_public_key_encrypt(const unsigned char *text,
		unsigned char *cipher, RSA_KEY_HANDLE_T *key_t) {
	if ((NULL == text) || (NULL == cipher) || (NULL == key_t)) {
		set_error_info(__FILE__, __FUNCTION__, __LINE__, ERR_PARAMETERS_NULL);
		return -1;
	}

	if (NULL == key_t->rsa_pub){
		set_error_info(__FILE__, __FUNCTION__, __LINE__, ERR_PARAMETERS_NULL);
		return -1;
	}

	if (0 >= key_t->padding) {
		set_error_info(__FILE__, __FUNCTION__, __LINE__, ERR_PADDING_PARAMETER);
		return -1;
	}

	int flen = FIPS_rsa_size(key_t->rsa_pub);
	if (flen < strlen(text)) {
		set_error_info(__FILE__, __FUNCTION__, __LINE__, ERR_LENGTH_INVALID);
		return -1;
	}

	int len = FIPS_rsa_public_encrypt(flen, text, cipher, key_t->rsa_pub, \
																		key_t->padding);
	if (0 > len)
		set_error_info(__FILE__, __FUNCTION__, __LINE__, ERR_get_error());
	return len;
}

int CRYPTO_RSA_private_key_decrypt(const unsigned char *cipher, \
																unsigned char *text, RSA_KEY_HANDLE_T *key_t) {
	int i = 0, flen = 0;
	unsigned char *cipher_tmp = NULL;
	unsigned char *text_tmp = NULL;

	if ((NULL == text) || (NULL == cipher) || (NULL == key_t) \
			|| (NULL == key_t->rsa_pri)) {
		set_error_info(__FILE__, __FUNCTION__, __LINE__, ERR_PARAMETERS_NULL);
		return -1;
	}

	if (0 >= key_t->padding) {
		set_error_info(__FILE__, __FUNCTION__, __LINE__, ERR_PADDING_PARAMETER);
		return -1;
	}

	flen = FIPS_rsa_size(key_t->rsa_pri);
	if (flen < strlen(cipher)) {
		set_error_info(__FILE__, __FUNCTION__, __LINE__, ERR_LENGTH_INVALID);
		return -1;
	}

	int len = FIPS_rsa_private_decrypt(flen, cipher, text, key_t->rsa_pri,
			key_t->padding);
	if (0 > len)
		set_error_info(__FILE__, __FUNCTION__, __LINE__, ERR_get_error());
	return len;
}

int CRYPTO_AES_key_generate(AES_KEY_HANDLE_T *key_t) {
	int key_len = 0, i = 0, j = 0;
	unsigned char AesRandNum[32] = { 0 };

	if (NULL == key_t) {
		set_error_info(__FILE__, __FUNCTION__, __LINE__, ERR_PARAMETERS_NULL);
		return -1;
	}

	if (key_t->key_bits == 128) {
		key_len = 16;
	} else if (key_t->key_bits == 192) {
		key_len = 24;
	} else if (key_t->key_bits == 256) {
		key_len = 32;
	} else {
		set_error_info(__FILE__, __FUNCTION__, __LINE__, ERR_BITS_INVALID);
		return -1;
	}

	if (0 > RAND_bytes(AesRandNum, key_len)) {
		set_error_info(__FILE__, __FUNCTION__, __LINE__, ERR_get_error());
		return -1;
	}

	for (i = 0, j = 0; i < key_len; i++, j += 2) {
		sprintf(&key_t->hex_key_str[j], "%02x", AesRandNum[i]);
	}

	memcpy(&key_t->key, &AesRandNum, key_len);

	return 0;
}

int CRYPTO_AES_init(AES_KEY_HANDLE_T *key_t) {
	char tmp[3] = { 0 };
	int i = 0, j = 0;

	if (NULL == key_t) {
		set_error_info(__FILE__, __FUNCTION__, __LINE__, ERR_PARAMETERS_NULL);
		return -1;
	}

	key_t->ctx = (EVP_CIPHER_CTX*) malloc(sizeof(EVP_CIPHER_CTX));
	if (NULL == key_t->ctx) {
		perror("malloc:");
		return -1;
	}

	FIPS_cipher_ctx_init(key_t->ctx);

	for (i = 0, j = 0; j < strlen(key_t->hex_key_str); i++, j += 2) {
		memset(tmp, 0, sizeof(tmp));
		strncpy(tmp, &key_t->hex_key_str[j], 2);
		key_t->key[i] = strtol(tmp, NULL, 16);
	}

	return 0;
}

int CRYPTO_AES_release(AES_KEY_HANDLE_T *key_t) {
	if (NULL == key_t) {
		set_error_info(__FILE__, __FUNCTION__, __LINE__, ERR_PARAMETERS_NULL);
		return -1;
	}

	if (key_t->ctx){
		FIPS_cipher_ctx_cleanup(key_t->ctx);
		key_t->ctx = NULL;
	}

	memset((char*) key_t, 0, sizeof(AES_KEY_HANDLE_T));

	return 0;
}

static const EVP_CIPHER *AES_feedback_mode(int type) {
	switch (type) {
	case AES_128_ECB:
		return FIPS_evp_aes_128_ecb();
	case AES_128_OFB:
		return FIPS_evp_aes_128_ofb();
	case AES_128_CTR:
		return FIPS_evp_aes_128_ctr();
	case AES_128_XTS:
		return FIPS_evp_aes_128_xts();
	case AES_256_ECB:
		return FIPS_evp_aes_256_ecb();
	case AES_256_OFB:
		return FIPS_evp_aes_256_ofb();
	case AES_256_CTR:
		return FIPS_evp_aes_256_ctr();
	case AES_256_XTS:
		return FIPS_evp_aes_256_xts();
	default:
		return NULL;
	}
	return NULL;
}

int CRYPTO_AES_encrypt(const unsigned char *text, unsigned char *cipher, \
											unsigned int len, AES_KEY_HANDLE_T *key_t) {
	if (NULL == text || NULL == cipher || NULL == key_t) {
		set_error_info(__FILE__, __FUNCTION__, __LINE__, ERR_PARAMETERS_NULL);
		return -1;
	}

	if (0 >= FIPS_cipherinit(key_t->ctx, AES_feedback_mode(key_t->feedback_mode), \
													&key_t->key[0], &key_t->IV[0], 1)) {
		set_error_info(__FILE__, __FUNCTION__, __LINE__, ERR_get_error());
		return -1;
	}

	FIPS_cipher(key_t->ctx, cipher, text, len);
	return 0;
}

int CRYPTO_AES_decrypt(const unsigned char *cipher, unsigned char *text, \
												unsigned int len, AES_KEY_HANDLE_T *key_t) {
	if (NULL == text || NULL == cipher || NULL == key_t) {
		set_error_info(__FILE__, __FUNCTION__, __LINE__, ERR_PARAMETERS_NULL);
		return -1;
	}

	if (0 >= FIPS_cipherinit(key_t->ctx, AES_feedback_mode(key_t->feedback_mode), \
													&key_t->key[0], &key_t->IV[0], 0)) {
		set_error_info(__FILE__, __FUNCTION__, __LINE__, ERR_get_error());
		return -1;
	}

	FIPS_cipher(key_t->ctx, text, cipher, len);
	return 0;
}

int CRYPTO_to_base64(const unsigned char *input, int input_len, char **output) {
	BIO *bmem = NULL, *b64 = NULL;
	BUF_MEM *bptr = NULL;
	int write_len = 0;

	if ((NULL == input) || (0 >= input_len)) {
		set_error_info(__FILE__, __FUNCTION__, __LINE__, ERR_PARAMETERS_NULL);
		return -1;
	}

	b64 = BIO_new(BIO_f_base64());
	bmem = BIO_new(BIO_s_mem());
	b64 = BIO_push(b64, bmem);
	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
	BIO_write(b64, input, input_len);
	BIO_flush(b64);
	BIO_get_mem_ptr(b64, &bptr);

	char *buffer = (char *) malloc(bptr->length + 1);
	if (NULL == buffer) {
		set_error_info(__FILE__, __FUNCTION__, __LINE__, ERR_LENGTH_INVALID);
		return -1;
	}
	memset(buffer, 0, bptr->length + 1);

	memcpy(buffer, bptr->data, bptr->length);
	*output = buffer;
	write_len = bptr->length;

	BIO_free_all(b64);
	b64 = NULL;

	return write_len;
}

int CRYPTO_from_base64(const unsigned char *input, int input_len, char **output) {
	BIO *b64, *bmem;
	int read_len = 0;

	if ((NULL == input) || (0 >= input_len)) {
		set_error_info(__FILE__, __FUNCTION__, __LINE__, ERR_PARAMETERS_NULL);
		return -1;
	}

	char *buffer = (char *) malloc(input_len + 1);
	if (NULL == buffer) {
		set_error_info(__FILE__, __FUNCTION__, __LINE__, ERR_LENGTH_INVALID);
		return -1;
	}
	memset(buffer, 0, input_len + 1);

	b64 = BIO_new(BIO_f_base64());
	bmem = BIO_new_mem_buf(input, input_len);
	bmem = BIO_push(b64, bmem);
	BIO_set_flags(bmem, BIO_FLAGS_BASE64_NO_NL);
	read_len = BIO_read(bmem, buffer, input_len);

	*output = buffer;

	BIO_free_all(bmem);
	bmem = NULL;

	return read_len;
}
