#include <crypto/aead.h>
#include <crypto/hash.h>
#include <crypto/internal/cipher.h>
#include <crypto/skcipher.h>
#include <linux/crypto.h>
#include <linux/err.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/ktime.h>
#include <linux/module.h>
#include <linux/scatterlist.h>
#include <linux/workqueue.h>


struct sdesc {
	struct shash_desc *shash;
	void *align_buf;
	void *align_digest;
	unsigned long alignmask;
	struct crypto_shash *tfm;
	u8 key[64];
	int keysize;
};

struct skcipher_desc {
	struct crypto_skcipher *tfm;
	struct skcipher_request *req;
	int (*cipher)(struct skcipher_request *req);
	//DECLARE_CRYPTO_WAIT(wait);
	struct crypto_wait wait;
	u8 key[64];
	u8 iv[16];
	int keysize;
	int encrypt_mode;
};

struct cipher_desc {
	struct crypto_cipher *tfm;
	void (*cipher)(struct crypto_cipher *tfm, u8 *dst, const u8 *src);
	u8 key[16];
	int keysize;
	int encrypt_mode;
};

struct aead_desc {
	struct crypto_aead *tfm;
	struct aead_request *req;
	struct crypto_wait wait;
	u8 key[64];
	u8 iv[16];
	int keysize;
	int encrypt_mode;
};

enum {
	ALG_SHASH = 0,
	ALG_SKCIPHER,
	ALG_CIPHER,
	ALG_AEAD,
};

struct generic_desc {
	union {
		struct sdesc		s;
		struct skcipher_desc	sk;
		struct cipher_desc	c;
		struct aead_desc	ad;
	};
	void *buf;
	int len;	// buffer length
	void *digest;
	int digest_len;
	int alg_type;
	char *alg_name;
};

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Haojian Zhuang");
MODULE_DESCRIPTION("A simple module for crypto.");
MODULE_VERSION("0.1");

MODULE_IMPORT_NS(CRYPTO_INTERNAL);

// The default hash algorithm is MD5.
//static char *hash_name = "md5-generic";
//static char *hash_name = "sha1-generic";
//static char *hash_name = "sha512-generic";
//static char *hash_name = "sha256-generic";
//static char *hash_name = "chacha20-generic";
static char *hash_name = "md4-generic";
// charp means char pointer
module_param(hash_name, charp, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
//MODULE_PARAM_DESC(hash_name, "Run the hash algorithm.");
//
static char *alg_name = "xts(aes)";
module_param(alg_name, charp, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);

static int buf_size = PAGE_SIZE;
module_param(buf_size, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);

static int key_bits = 128;
module_param(key_bits, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);

static int encrypt_mode = 1;
module_param(encrypt_mode, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);

static char *mode_name = "perf";
module_param(mode_name, charp, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);

static struct workqueue_struct *hash_workqueue;

static void dump_digest(unsigned char *digest, int digest_len)
{
	print_hex_dump(KERN_INFO, "Hash digest: ", DUMP_PREFIX_NONE, 32, 1,
			digest, digest_len, 0);
}

static int is_skcipher_alg(char *alg_name)
{
	if (!strcmp(alg_name, "xts(aes)"))
		return 1;
	if (!strcmp(alg_name, "cbc(aes)") ||
		!strcmp(alg_name, "cbc(aes-generic)") ||
		!strcmp(alg_name, "cbc(aes-ce)") ||
		!strcmp(alg_name, "cbc-aes-ce") ||
		!strcmp(alg_name, "cbc-aes-neonbs"))
		return 1;
	if (!strcmp(alg_name, "ecb(aes)") ||
		!strcmp(alg_name, "ecb(aes-generic)") ||
		!strcmp(alg_name, "ecb(aes-ce)") ||
		!strcmp(alg_name, "ecb-aes-ce") ||
		!strcmp(alg_name, "ecb-aes-neonbs"))
		return 1;
	if (!strcmp(alg_name, "cbc-sm4-neon") ||
		!strcmp(alg_name, "cbc(sm4-generic)") ||
		!strcmp(alg_name, "cbc-sm4-ce") ||
		!strcmp(alg_name, "ecb-sm4-neon") ||
		!strcmp(alg_name, "ecb(sm4-generic)") ||
		!strcmp(alg_name, "ecb-sm4-ce") ||
		!strcmp(alg_name, "cbc(sm4)") ||
		!strcmp(alg_name, "ecb(sm4)"))
		return 1;
	return 0;
}

static int is_cipher_alg(char *alg_name)
{
	if (!strcmp(alg_name, "sm4") ||
		!strcmp(alg_name, "sm4-generic") ||
		!strcmp(alg_name, "sm4-ce"))
		return 1;
	return 0;
}

static int is_aead_alg(char *alg_name)
{
	if (!strcmp(alg_name, "gcm(aes)"))
		return 1;
	if (!strcmp(alg_name, "gcm(sm4)"))
		return 1;
	return 0;
}

static int is_hash_alg(char *alg_name)
{
	if (!strcmp(alg_name, "md4-generic"))
		return 1;
	if (!strcmp(alg_name, "md5-generic"))
		return 1;
	if (!strcmp(alg_name, "sha1-generic"))
		return 1;
	if (!strcmp(alg_name, "sha1-ce"))
		return 1;
	if (!strcmp(alg_name, "sha1-ssse3"))
		return 1;
	if (!strcmp(alg_name, "sha1-avx"))
		return 1;
	if (!strcmp(alg_name, "sha1-avx2"))
		return 1;
	if (!strcmp(alg_name, "sha256-generic"))
		return 1;
	if (!strcmp(alg_name, "sha256-arm64-neon"))
		return 1;
	if (!strcmp(alg_name, "sha256-ce"))
		return 1;
	if (!strcmp(alg_name, "sha256-ssse3"))
		return 1;
	if (!strcmp(alg_name, "sha256-avx"))
		return 1;
	if (!strcmp(alg_name, "sha256-avx2"))
		return 1;
	if (!strcmp(alg_name, "sha512-generic"))
		return 1;
	if (!strcmp(alg_name, "sha512-ce"))
		return 1;
	if (!strcmp(alg_name, "sha512-ssse3") || !strcmp(alg_name, "sha512-avx") ||
		!strcmp(alg_name, "sha512-avx2"))
		return 1;
	if (!strcmp(alg_name, "sha3-generic"))
		return 1;
	if (!strcmp(alg_name, "sha3-ce"))
		return 1;
	if (!strcmp(alg_name, "sha3-256-generic"))
		return 1;
	if (!strcmp(alg_name, "sha3-256-ce"))
		return 1;
	if (!strcmp(alg_name, "sha3-384-generic"))
		return 1;
	if (!strcmp(alg_name, "sha3-384-ce"))
		return 1;
	if (!strcmp(alg_name, "sha3-512-generic"))
		return 1;
	if (!strcmp(alg_name, "sha3-512-ce"))
		return 1;
	if (!strcmp(alg_name, "chacha20-generic"))
		return 1;
	if (!strcmp(alg_name, "chacha20-neon"))
		return 1;
	if (!strcmp(alg_name, "sm3-generic"))
		return 1;
	if (!strcmp(alg_name, "sm3-ce"))
		return 1;
	if (!strcmp(alg_name, "sm3-avx"))
		return 1;
	if (!strcmp(alg_name, "hmac(md5)"))
		return 1;
	if (!strcmp(alg_name, "hmac(sha1)"))
		return 1;
	if (!strcmp(alg_name, "hmac(sha256)"))
		return 1;
	if (!strcmp(alg_name, "hmac(sha512)"))
		return 1;
	return 0;
}

static int init_cipher(struct generic_desc *desc,
			struct crypto_cipher *tfm)
{
	u8 sm4_key[] = "\x01\x23\x45\x67\x89\xab\xcd\xef"
			"\xfe\xdc\xba\x98\x76\x54\x32\x10";
	u8 sm4_ptext[] = "\x01\x23\x45\x67\x89\xab\xcd\xef"
			"\xfe\xdc\xba\x98\x76\x54\x32\x10";
	u8 sm4_ctext[] = "\x68\x1e\xdf\x34\xd2\x06\x96\x5e"
			"\x86\xb3\xe9\x4f\x53\x6e\x42\x46";
	int src_size;
	size_t bsize;

	memset(desc->c.key, 0, desc->c.keysize);
	memcpy(desc->c.key, sm4_key, strlen(sm4_key));
	memset(desc->buf, 0, desc->len);
	bsize = crypto_cipher_blocksize(tfm);
	if (desc->c.encrypt_mode) {
		memcpy(desc->buf, sm4_ptext, sizeof(sm4_ptext));
		src_size = max(strlen(sm4_ptext), bsize);
	} else {
		memcpy(desc->buf, sm4_ctext, sizeof(sm4_ctext));
		src_size = max(strlen(sm4_ctext), bsize);
	}
	src_size = ALIGN(src_size, bsize);
	if (src_size > desc->len) {
		pr_err("Error. Source size (%d) exceeds limit (%d).\n",
			src_size, desc->len);
		return -EINVAL;
	}
	desc->len = src_size;
	return 0;
}

static void measure_algm(struct generic_desc *desc)
{
	ktime_t kt_start, kt_end, kt_val;
	int count = 0;
	s64 delta_us;
	s64 bytes;
	int ret;

	kt_start = ktime_get();
	kt_val = ktime_add_ms(kt_start, 3000);
	do {
		if (desc->alg_type == ALG_SHASH) {
			crypto_shash_digest(desc->s.shash, desc->buf, desc->len, desc->digest);
		} else if (desc->alg_type == ALG_SKCIPHER) {
			ret = desc->sk.cipher(desc->sk.req);
			ret = crypto_wait_req(ret, &desc->sk.wait);
			if (ret) {
				pr_err("Error encrypt/decrypt data: %d\n", ret);
				break;
			}
		} else if (desc->alg_type == ALG_CIPHER) {
			int len, bsize;
			bsize = crypto_cipher_blocksize(desc->c.tfm);
			for (len = buf_size; len > 0;) {
				desc->c.cipher(desc->c.tfm, desc->digest,
						desc->buf);
				len = len - bsize;
			}
		} else
			break;
		kt_end = ktime_get();
		count++;
	} while (ktime_before(kt_end, kt_val));
	delta_us = ktime_us_delta(kt_end, kt_start);
	bytes = (s64)count * (s64)buf_size;
	if (ret) {
		pr_info("Error on running algorithm: %d\n", ret);
	} else {
		pr_info("count:%d, len:%d, bytes:%lld\n",
			count, buf_size, bytes);
		pr_info("Bandwith: %lldMB/s (%lldB, %lldus)\n",
			bytes / delta_us, bytes, delta_us);
	}
}

static int run_shash(struct generic_desc *desc)
{
	struct crypto_shash *tfm = NULL;
	unsigned long alignmask;
	void *align_buf, *align_digest;

	tfm = crypto_alloc_shash(alg_name, 0, 0);
	if (IS_ERR(tfm)) {
		pr_err("Can't allocate SHASH %s (%ld)\n",
			alg_name, PTR_ERR(tfm));
		return PTR_ERR(tfm);
	}
	if (!strcmp(alg_name, "hmac(md5)") ||
		!strcmp(alg_name, "hmac(sha1)") ||
		!strcmp(alg_name, "hmac(sha256)") ||
		!strcmp(alg_name, "hmac(sha512)")) {
		int ret;

		if (key_bits == 128)
			desc->s.keysize = 16;
		get_random_bytes(desc->s.key, desc->s.keysize);
		ret = crypto_shash_setkey(tfm, desc->s.key, desc->s.keysize);
		if (ret) {
			pr_err("Error on setting key: %d\n", ret);
			crypto_free_shash(tfm);
			return ret;
		}
	}
	desc->s.shash->tfm = tfm;
	desc->digest_len = crypto_shash_digestsize(tfm);
	alignmask = crypto_shash_alignmask(tfm);
	if (alignmask < 15)
		alignmask = 15;
	align_buf = (void *)ALIGN((unsigned long)desc->buf, alignmask);
	align_digest = (void *)((unsigned long)desc->digest & ~alignmask);
	//crypto_shash_digest(desc->s.shash, align_buf, desc->len, align_digest);
	measure_algm(desc);
	crypto_free_shash(tfm);
	return 0;
}

static int run_skcipher(struct generic_desc *desc)
{
	struct crypto_skcipher *tfm = NULL;
	struct skcipher_request *req = NULL;
	struct scatterlist sg;
	//DECLARE_CRYPTO_WAIT(wait);
	u8 iv[16];	/* AES-256-XTS takes a 16-byte IV */
	u8 key[64];	/* AES-256-XTS takes a 64-byte key */
	int ret = -EINVAL;

	init_completion(&desc->sk.wait.completion);
	desc->sk.wait.err = 0;
	if (key_bits == 128)
		desc->sk.keysize = 16;
	else if (key_bits == 192)
		desc->sk.keysize = 24;
	else if (key_bits == 256)
		desc->sk.keysize = 32;
	else {
		pr_err("Wrong key_bits (%d)\n", key_bits);
		return -EINVAL;
	}
	tfm = crypto_alloc_skcipher(alg_name, 0, 0);
	if (IS_ERR(tfm)) {
		pr_err("Can't allocate SKCIPHER %s (%ld)\n",
			alg_name, PTR_ERR(tfm));
		return PTR_ERR(tfm);
	}
	get_random_bytes(key, desc->sk.keysize);
	ret = crypto_skcipher_setkey(tfm, key, desc->sk.keysize);
	if (ret) {
		pr_err("Error on setting key: %d\n", ret);
		goto out;
	}

	/* Allocate a request object */
	req = skcipher_request_alloc(tfm, GFP_KERNEL);
	if (!req) {
		pr_err("Fail to request SKCIPHER object\n");
		goto out;
	}

	/* Initialize the IV */
	get_random_bytes(iv, sizeof(iv));

	sg_init_one(&sg, desc->buf, desc->len);
	skcipher_request_set_callback(req,
				      CRYPTO_TFM_REQ_MAY_BACKLOG |
				      CRYPTO_TFM_REQ_MAY_SLEEP,
				      crypto_req_done,
				      &desc->sk.wait);
	skcipher_request_set_crypt(req, &sg, &sg, desc->len, iv);
	desc->sk.req = req;
	if (desc->sk.encrypt_mode)
		desc->sk.cipher = crypto_skcipher_encrypt;
	else
		desc->sk.cipher = crypto_skcipher_decrypt;
	measure_algm(desc);
	skcipher_request_free(req);
	crypto_free_skcipher(tfm);
	return 0;
out:
	crypto_free_skcipher(tfm);
	return ret;
}

static int run_cipher(struct generic_desc *desc)
{
	struct crypto_cipher *tfm = NULL;
	int ret = -EINVAL;

	tfm = crypto_alloc_cipher(desc->alg_name, 0, 0);
	if (IS_ERR(tfm)) {
		pr_err("Can't allocate CIPHER %s (%ld)\n",
			alg_name, PTR_ERR(tfm));
		return PTR_ERR(tfm);
	}
	desc->c.tfm = tfm;
	init_cipher(desc, tfm);
	desc->len = buf_size;
	get_random_bytes(desc->buf, desc->len);
	ret = crypto_cipher_setkey(tfm, desc->c.key, desc->c.keysize);
	if (ret) {
		pr_err("Error on setting key: %d\n", ret);
		goto out;
	}
	if (desc->c.encrypt_mode)
		desc->c.cipher = crypto_cipher_encrypt_one;
	else
		desc->c.cipher = crypto_cipher_decrypt_one;
	measure_algm(desc);
	crypto_free_cipher(tfm);
	return 0;
out:
	crypto_free_cipher(tfm);
	return ret;
}

static int run_aead(struct generic_desc *desc)
{
	struct crypto_aead *tfm = NULL;
	struct aead_request *req = NULL;
	struct scatterlist sg_src, sg_dst;
	int ret = -EINVAL;

	tfm = crypto_alloc_aead(desc->alg_name, 0, 0);
	if (IS_ERR(tfm)) {
		pr_err("Can't allocate AEAD %s (%ld)\n",
			alg_name, PTR_ERR(tfm));
		return PTR_ERR(tfm);
	}

	req = aead_request_alloc(tfm, GFP_KERNEL);
	if (!req) {
		pr_err("Fail to allocate request for %s\n",
			alg_name);
		ret = -ENOMEM;
		goto out;
	}
	sg_init_one(&sg_src, desc->buf, desc->len);
	sg_init_one(&sg_dst, desc->digest, desc->digest_len);
	aead_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG |
				CRYPTO_TFM_REQ_MAY_SLEEP,
				crypto_req_done,
				&desc->ad.wait);
	aead_request_set_crypt(req, &sg_src, &sg_dst, desc->len, desc->ad.iv);
	if (desc->ad.encrypt_mode)
		ret = crypto_aead_encrypt(req);
	else
		ret = crypto_aead_decrypt(req);
	ret = crypto_wait_req(ret, &desc->ad.wait);
	if (ret) {
		pr_err("Error encrypt data: %d\n", ret);
		goto out_wait;
	}
	{
		pr_err("src:");
		dump_digest(desc->buf, desc->len);
		pr_err("dst:");
		dump_digest(desc->digest, desc->digest_len);
	}
	aead_request_free(req);
	crypto_free_aead(tfm);
	return 0;
out_wait:
	aead_request_free(req);
out:
	crypto_free_aead(tfm);
	return ret;
}

static int run_algm(struct generic_desc *desc)
{
	int ret = -EINVAL;

	if (desc->alg_type == ALG_SHASH)
		ret = run_shash(desc);
	else if (desc->alg_type == ALG_SKCIPHER)
		ret = run_skcipher(desc);
	else if (desc->alg_type == ALG_CIPHER)
		ret = run_cipher(desc);
	else if (desc->alg_type == ALG_AEAD)
		ret = run_aead(desc);
	return ret;
}

static void set_skcipher_key(struct generic_desc *desc)
{
	u8 iv[16];	/* AES-256-XTS takes a 16-byte IV */
	u8 key[64];	/* AES-256-XTS takes a 64-byte key */

	if (key_bits == 128) {
		memset(key, 0, sizeof(key));
		key[0] = 0x06;	key[1] = 0xa9;	key[2] = 0x21;	key[3] = 0x40;
		key[4] = 0x36;	key[5] = 0xb8;	key[6] = 0xa1;	key[7] = 0x5b;
		key[8] = 0x51;	key[9] = 0x2e;	key[10] = 0x03;	key[11] = 0xd5;
		key[12] = 0x34;	key[13] = 0x12;	key[14] = 0x00;	key[15] = 0x06;
		memcpy(desc->sk.key, key, 16);
		desc->sk.keysize = 16;
		memset(iv, 0, sizeof(iv));
		iv[0] = 0x3d;	iv[1] = 0xaf;	iv[2] = 0xba;	iv[3] = 0x42;
		iv[4] = 0x9d;	iv[5] = 0x9e;	iv[6] = 0xb4;	iv[7] = 0x30;
		iv[8] = 0xb4;	iv[9] = 0x22;	iv[10] = 0xda;	iv[11] = 0x80;
		iv[12] = 0x2c;	iv[13] = 0x9f;	iv[14] = 0xac;	iv[15] = 0x41;
		memcpy(desc->sk.iv, iv, 16);
	} else if (key_bits == 192) {
		memset(key, 0, sizeof(key));
		key[0] = 0x8e;	key[1] = 0x73;	key[2] = 0xb0;	key[3] = 0xf7;
		key[4] = 0xda;	key[5] = 0x0e;	key[6] = 0x64;	key[7] = 0x52;
		key[8] = 0xc8;	key[9] = 0x10;	key[10] = 0xf3;	key[11] = 0x2b;
		key[12] = 0x80;	key[13] = 0x90;	key[14] = 0x79;	key[15] = 0xe5;
		key[16] = 0x62;	key[17] = 0xf8;	key[18] = 0xea;	key[19] = 0xd2;
		key[20] = 0x52;	key[21] = 0x2c;	key[22] = 0x6b;	key[23] = 0x7b;
		memcpy(desc->sk.key, key, 24);
		desc->sk.keysize = 24;
		memset(iv, 0, sizeof(iv));
		iv[0] = 0x00;	iv[1] = 0x01;	iv[2] = 0x02;	iv[3] = 0x03;
		iv[4] = 0x04;	iv[5] = 0x05;	iv[6] = 0x06;	iv[7] = 0x07;
		iv[8] = 0x08;	iv[9] = 0x09;	iv[10] = 0x0a;	iv[11] = 0x0b;
		iv[12] = 0x0c;	iv[13] = 0x0d;	iv[14] = 0x0e;	iv[15] = 0x0f;
		memcpy(desc->sk.iv, iv, 16);
	} else if (key_bits == 256) {
		memset(key, 0, sizeof(key));
		key[0] = 0x60;	key[1] = 0x3d;	key[2] = 0xeb;	key[3] = 0x10;
		key[4] = 0x15;	key[5] = 0xca;	key[6] = 0x71;	key[7] = 0xbe;
		key[8] = 0x2b;	key[9] = 0x73;	key[10] = 0xae;	key[11] = 0xf0;
		key[12] = 0x85;	key[13] = 0x7d;	key[14] = 0x77;	key[15] = 0x81;
		key[16] = 0x1f;	key[17] = 0x35;	key[18] = 0x2c;	key[19] = 0x07;
		key[20] = 0x3b;	key[21] = 0x61;	key[22] = 0x08;	key[23] = 0xd7;
		key[24] = 0x2d;	key[25] = 0x98;	key[26] = 0x10;	key[27] = 0xa3;
		key[28] = 0x09;	key[29] = 0x14;	key[30] = 0xdf;	key[31] = 0xf4;
		memcpy(desc->sk.key, key, 32);
		desc->sk.keysize = 32;
		memset(iv, 0, sizeof(iv));
		iv[0] = 0x00;	iv[1] = 0x01;	iv[2] = 0x02;	iv[3] = 0x03;
		iv[4] = 0x04;	iv[5] = 0x05;	iv[6] = 0x06;	iv[7] = 0x07;
		iv[8] = 0x08;	iv[9] = 0x09;	iv[10] = 0x0a;	iv[11] = 0x0b;
		iv[12] = 0x0c;	iv[13] = 0x0d;	iv[14] = 0x0e;	iv[15] = 0x0f;
		memcpy(desc->sk.iv, iv, 16);
	}
}

static int init_skcipher(struct generic_desc *desc,
			struct crypto_skcipher *tfm)
{
	u8 aes_128_cbc_ptext[] = "Single block msg";
	u8 aes_192_cbc_ptext[] = "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96"
				"\xe9\x3d\x7e\x11\x73\x93\x17\x2a"
				"\xae\x2d\x8a\x57\x1e\x03\xac\x9c"
				"\x9e\xb7\x6f\xac\x45\xaf\x8e\x51"
				"\x30\xc8\x1c\x46\xa3\x5c\xe4\x11"
				"\xe5\xfb\xc1\x19\x1a\x0a\x52\xef"
				"\xf6\x9f\x24\x45\xdf\x4f\x9b\x17"
				"\xad\x2b\x41\x7b\xe6\x6c\x37\x10";
	u8 aes_256_cbc_ptext[] = "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96"
				"\xe9\x3d\x7e\x11\x73\x93\x17\x2a"
				"\xae\x2d\x8a\x57\x1e\x03\xac\x9c"
				"\x9e\xb7\x6f\xac\x45\xaf\x8e\x51"
				"\x30\xc8\x1c\x46\xa3\x5c\xe4\x11"
				"\xe5\xfb\xc1\x19\x1a\x0a\x52\xef"
				"\xf6\x9f\x24\x45\xdf\x4f\x9b\x17"
				"\xad\x2b\x41\x7b\xe6\x6c\x37\x10";
	u8 sm4_cbc_ptext[] = "\xaa\xaa\xaa\xaa\xbb\xbb\xbb\xbb"
				"\xcc\xcc\xcc\xcc\xdd\xdd\xdd\xdd"
				"\xee\xee\xee\xee\xff\xff\xff\xff"
				"\xaa\xaa\xaa\xaa\xbb\xbb\xbb\xbb";
	u8 aes_128_cbc_ctext[] = "\xe3\x53\x77\x9c\x10\x79\xae\xb8"
				"\x27\x08\x94\x2d\xbe\x77\x18\x1a";
	u8 aes_192_cbc_ctext[] = "\x4f\x02\x1d\xb2\x43\xbc\x63\x3d"
				"\x71\x78\x18\x3a\x9f\xa0\x71\xe8"
				"\xb4\xd9\xad\xa9\xad\x7d\xed\xf4"
				"\xe5\xe7\x38\x76\x3f\x69\x14\x5a"
				"\x57\x1b\x24\x20\x12\xfb\x7a\xe0"
				"\x7f\xa9\xba\xac\x3d\xf1\x02\xe0"
				"\x08\xb0\xe2\x79\x88\x59\x88\x81"
				"\xd9\x20\xa9\xe6\x4f\x56\x15\xcd";
	u8 aes_256_cbc_ctext[] = "\xf5\x8c\x4c\x04\xd6\xe5\xf1\xba"
				"\x77\x9e\xab\xfb\x5f\x7b\xfb\xd6"
				"\x9c\xfc\x4e\x96\x7e\xdb\x80\x8d"
				"\x67\x9f\x77\x7b\xc6\x70\x2c\x7d"
				"\x39\xf2\x33\x69\xa9\xd9\xba\xcf"
				"\xa5\x30\xe2\x63\x04\x23\x14\x61"
				"\xb2\xeb\x05\xe2\xc3\x9b\xe9\xfc"
				"\xda\x6c\x19\x07\x8c\x6a\x9d\x1b";
	u8 aes_128_ecb_ctext[] = "\x3a\xe0\x0f\xbd\x31\xdf\xae\xed"
				"\x4d\xa6\xe4\x4f\xe2\xc1\x1b\x4f";
	u8 aes_192_ecb_ctext[] = "\xbd\x33\x4f\x1d\x6e\x45\xf2\x5f"
				"\xf7\x12\xa2\x14\x57\x1f\xa5\xcc"
				"\x97\x41\x04\x84\x6d\x0a\xd3\xad"
				"\x77\x34\xec\xb3\xec\xee\x4e\xef"
				"\xef\x7a\xfd\x22\x70\xe2\xe6\x0a"
				"\xdc\xe0\xba\x2f\xac\xe6\x44\x4e"
				"\x9a\x4b\x41\xba\x73\x8d\x6c\x72"
				"\xfb\x16\x69\x16\x03\xc1\x8e\x0e";
	u8 aes_256_ecb_ctext[] = "\xf3\xee\xd1\xbd\xb5\xd2\xa0\x3c"
				"\x06\x4b\x5a\x7e\x3d\xb1\x81\xf8"
				"\x59\x1c\xcb\x10\xd4\x10\xed\x26"
				"\xdc\x5b\xa7\x4a\x31\x36\x28\x70"
				"\xb6\xed\x21\xb9\x9c\xa6\xf4\xf9"
				"\xf1\x53\xe7\xb1\xbe\xaf\xed\x1d"
				"\x23\x30\x4b\x7a\x39\xf9\xf3\xff"
				"\x06\x7d\x8d\x8f\x9e\x24\xec\xc7";
	u8 sm4_cbc_ctext[] = "\x78\xeb\xb1\x1c\xc4\x0b\x0a\x48"
				"\x31\x2a\xae\xb2\x04\x02\x44\xcb"
				"\x4c\xb7\x01\x69\x51\x90\x92\x26"
				"\x97\x9b\x0d\x15\xdc\x6a\x8f\x6d";
	int src_size;
	size_t bsize;

	set_skcipher_key(desc);
	memset(desc->buf, 0, desc->len);
	bsize = crypto_skcipher_blocksize(tfm);
	if (!strcmp(desc->alg_name, "cbc(aes)") ||
		!strcmp(desc->alg_name, "cbc(aes-generic)") ||
		!strcmp(desc->alg_name, "cbc(aes-ce)") ||
		!strcmp(desc->alg_name, "cbc-aes-ce") ||
		!strcmp(desc->alg_name, "cbc-aes-neonbs")) {
		if (key_bits == 128) {
			// aes-128-cbc
			if (desc->sk.encrypt_mode) {
				memcpy(desc->buf, aes_128_cbc_ptext, sizeof(aes_128_cbc_ptext));
				src_size = max(strlen(aes_128_cbc_ptext), bsize);
			} else {
				memcpy(desc->buf, aes_128_cbc_ctext, sizeof(aes_128_cbc_ctext));
				src_size = max(strlen(aes_128_cbc_ctext), bsize);
			}
		} else if (key_bits == 192) {
			// aes-192-cbc
			if (desc->sk.encrypt_mode) {
				memcpy(desc->buf, aes_192_cbc_ptext, sizeof(aes_192_cbc_ptext));
				src_size = max(strlen(aes_192_cbc_ptext), bsize);
			} else {
				memcpy(desc->buf, aes_192_cbc_ctext, sizeof(aes_192_cbc_ctext));
				src_size = max(strlen(aes_192_cbc_ctext), bsize);
			}
		} else if (key_bits == 256) {
			// aes-256-cbc
			if (desc->sk.encrypt_mode) {
				memcpy(desc->buf, aes_256_cbc_ptext, sizeof(aes_256_cbc_ptext));
				src_size = max(strlen(aes_256_cbc_ptext), bsize);
			} else {
				memcpy(desc->buf, aes_256_cbc_ctext, sizeof(aes_256_cbc_ctext));
				src_size = max(strlen(aes_256_cbc_ctext), bsize);
			}
		}
	} else if (!strcmp(desc->alg_name, "ecb(aes)") ||
			!strcmp(desc->alg_name, "ecb(aes-generic)") ||
			!strcmp(desc->alg_name, "ecb(aes-ce)") ||
			!strcmp(desc->alg_name, "ecb-aes-neonbs") ||
			!strcmp(desc->alg_name, "ecb-aes-ce")) {
		if (key_bits == 128) {
			// aes-128-ecb
			if (desc->sk.encrypt_mode) {
				memcpy(desc->buf, aes_128_cbc_ptext, sizeof(aes_128_cbc_ptext));
				src_size = max(strlen(aes_128_cbc_ptext), bsize);
			} else {
				memcpy(desc->buf, aes_128_ecb_ctext, sizeof(aes_128_ecb_ctext));
				src_size = max(strlen(aes_128_ecb_ctext), bsize);
			}
		} else if (key_bits == 192) {
			// aes-192-ecb
			if (desc->sk.encrypt_mode) {
				memcpy(desc->buf, aes_192_cbc_ptext, sizeof(aes_192_cbc_ptext));
				src_size = max(strlen(aes_192_cbc_ptext), bsize);
			} else {
				memcpy(desc->buf, aes_192_ecb_ctext, sizeof(aes_192_ecb_ctext));
				src_size = max(strlen(aes_192_ecb_ctext), bsize);
			}
		} else if (key_bits == 256) {
			// aes-256-ecb
			if (desc->sk.encrypt_mode) {
				memcpy(desc->buf, aes_256_cbc_ptext, sizeof(aes_256_cbc_ptext));
				src_size = max(strlen(aes_256_cbc_ptext), bsize);
			} else {
				memcpy(desc->buf, aes_256_ecb_ctext, sizeof(aes_256_ecb_ctext));
				src_size = max(strlen(aes_256_ecb_ctext), bsize);
			}
		}
	} else if (!strcmp(desc->alg_name, "cbc(sm4-generic)") ||
			!strcmp(desc->alg_name, "cbc-sm4-neon") ||
			!strcmp(desc->alg_name, "cbc-sm4-ce") ||
			!strcmp(desc->alg_name, "cbc(sm4)") ||
			!strcmp(desc->alg_name, "ecb(sm4-generic)") ||
			!strcmp(desc->alg_name, "ecb-sm4-neon") ||
			!strcmp(desc->alg_name, "ecb-sm4-ce") ||
			!strcmp(desc->alg_name, "ecb(sm4)")) {
		if (desc->c.encrypt_mode) {
			memcpy(desc->buf, sm4_cbc_ptext, strlen(sm4_cbc_ptext));
			src_size = max(strlen(sm4_cbc_ptext), bsize);
		} else {
			memcpy(desc->buf, sm4_cbc_ctext, strlen(sm4_cbc_ctext));
			src_size = max(strlen(sm4_cbc_ctext), bsize);
		}
	}
	src_size = ALIGN(src_size, bsize);
	if (src_size > desc->len) {
		pr_err("Error. Source size (%d) exceeds limit (%d).\n",
			src_size, desc->len);
		return -EINVAL;
	}
	desc->len = src_size;
	desc->digest_len = desc->len;
	return 0;
}

static void set_shash_key(struct generic_desc *desc)
{
	u8 key[64];

	if (key_bits == 128) {
		memset(key, 0, sizeof(key));
		key[0] = 0x0b;	key[1] = 0x0b;	key[2] = 0x0b;	key[3] = 0x0b;
		key[4] = 0x0b;	key[5] = 0x0b;	key[6] = 0x0b;	key[7] = 0x0b;
		key[8] = 0x0b;	key[9] = 0x0b;	key[10] = 0x0b;	key[11] = 0x0b;
		key[12] = 0x0b;	key[13] = 0x0b;	key[14] = 0x0b;	key[15] = 0x0b;
		memcpy(desc->s.key, key, 16);
		desc->s.keysize = 16;
	}
}

static int init_shash(struct generic_desc *desc, struct crypto_shash *tfm)
{
	u8 hmac_128_md5_ptext[] = "Hi There";
	/*
	u8 hmac_128_md5_ctext[] = "\x92\x94\x72\x7a\x36\x38\xbb\x1c"
				"\x13\xf4\x8e\xf8\x15\x8b\xfc\x9d";
	*/
	int src_size;

	if (!strcmp(desc->alg_name, "hmac(md5)")) {
		set_shash_key(desc);
		memset(desc->buf, 0, desc->len);
		memcpy(desc->buf, hmac_128_md5_ptext, strlen(hmac_128_md5_ptext));
		src_size = strlen(hmac_128_md5_ptext);
		if (src_size > desc->len) {
			pr_err("Error. Source size (%d) exceeds limit (%d).\n",
				src_size, desc->len);
			return -EINVAL;
		}
		desc->len = src_size;
		desc->digest_len = 16;
	}
	return 0;
}

static int test_shash(struct generic_desc *desc)
{
	struct crypto_shash *tfm = NULL;
	unsigned long alignmask;
	void *align_buf, *align_digest;
	int ret;

	tfm = crypto_alloc_shash(alg_name, 0, 0);
	if (IS_ERR(tfm)) {
		pr_err("Can't allocate SHASH %s (%ld)\n",
			alg_name, PTR_ERR(tfm));
		return PTR_ERR(tfm);
	}
	desc->s.shash->tfm = tfm;
	desc->digest_len = crypto_shash_digestsize(tfm);
	alignmask = crypto_shash_alignmask(tfm);
	if (alignmask < 15)
		alignmask = 15;
	align_buf = (void *)ALIGN((unsigned long)desc->buf, alignmask);
	align_digest = (void *)((unsigned long)desc->digest & ~alignmask);
	init_shash(desc, tfm);
	ret = crypto_shash_setkey(tfm, desc->s.key, desc->s.keysize);
	if (ret) {
		pr_err("Error on setting key: %d\n", ret);
		goto out;
	}
	crypto_shash_digest(desc->s.shash, desc->buf, desc->len, desc->digest);
	crypto_free_shash(tfm);
	{
		pr_err("src:");
		dump_digest(desc->buf, desc->len);
		pr_err("dst:");
		dump_digest(desc->digest, desc->digest_len);
	}
	return 0;
out:
	crypto_free_shash(tfm);
	return ret;
}

static int test_skcipher(struct generic_desc *desc)
{
	struct crypto_skcipher *tfm = NULL;
	struct skcipher_request *req = NULL;
	struct scatterlist sg_src, sg_dst;
	DECLARE_CRYPTO_WAIT(wait);
	int ret = -EINVAL;

	tfm = crypto_alloc_skcipher(alg_name, 0, 0);
	if (IS_ERR(tfm)) {
		pr_err("Can't allocate SKCIPHER %s (%ld)\n",
			alg_name, PTR_ERR(tfm));
		return PTR_ERR(tfm);
	}
	init_skcipher(desc, tfm);
	ret = crypto_skcipher_setkey(tfm, desc->sk.key, desc->sk.keysize);
	if (ret) {
		pr_err("Error on setting key: %d\n", ret);
		goto out;
	}

	/* Allocate a request object */
	req = skcipher_request_alloc(tfm, GFP_KERNEL);
	if (!req) {
		pr_err("Fail to request SKCIPHER object\n");
		goto out;
	}

	/* Initialize the IV */

	sg_init_one(&sg_src, desc->buf, desc->len);
	sg_init_one(&sg_dst, desc->digest, desc->digest_len);
	skcipher_request_set_callback(req,
				      CRYPTO_TFM_REQ_MAY_BACKLOG |
				      CRYPTO_TFM_REQ_MAY_SLEEP,
				      crypto_req_done,
				      &wait);
	skcipher_request_set_crypt(req, &sg_src, &sg_dst, desc->len,
				desc->sk.iv);
	if (desc->sk.encrypt_mode)
		ret = crypto_skcipher_encrypt(req);
	else
		ret = crypto_skcipher_decrypt(req);
	ret = crypto_wait_req(ret, &wait);
	if (ret) {
		pr_err("Error encrypt data: %d\n", ret);
		goto out_wait;
	}
	{
		pr_err("src:");
		dump_digest(desc->buf, desc->len);
		pr_err("dst:");
		dump_digest(desc->digest, desc->digest_len);
	}
	skcipher_request_free(req);
	crypto_free_skcipher(tfm);
	return 0;
out_wait:
	skcipher_request_free(req);
out:
	crypto_free_skcipher(tfm);
	return ret;
}

static int test_cipher(struct generic_desc *desc)
{
	struct crypto_cipher *tfm = NULL;
	int ret = -EINVAL, bsize, len;

	tfm = crypto_alloc_cipher(alg_name, 0, 0);
	if (IS_ERR(tfm)) {
		pr_err("Can't allocate CIPHER %s (%ld)\n",
			alg_name, PTR_ERR(tfm));
		return PTR_ERR(tfm);
	}
	init_cipher(desc, tfm);
	desc->digest_len = desc->len;
	ret = crypto_cipher_setkey(tfm, desc->c.key, desc->c.keysize);
	if (ret) {
		pr_err("Error on setting key: %d\n", ret);
		goto out;
	}
	bsize = crypto_cipher_blocksize(tfm);
	for (len = desc->len; len > 0;) {
		if (desc->c.encrypt_mode)
			crypto_cipher_encrypt_one(tfm, desc->digest,
						desc->buf);
		else
			crypto_cipher_decrypt_one(tfm, desc->digest,
						desc->buf);
		len = len - bsize;
	}
	{
		pr_err("src:");
		dump_digest(desc->buf, desc->len);
		pr_err("dst:");
		dump_digest(desc->digest, desc->digest_len);
	}
	crypto_free_cipher(tfm);
	return 0;
out:
	crypto_free_cipher(tfm);
	return ret;
}

static void set_aead_key(struct generic_desc *desc)
{
	u8 iv[16];
	u8 key[64];

	if (key_bits == 128) {
		pr_err("key_bits equals to 128\n");
		memset(key, 0, sizeof(key));
		key[0] = 0xfe;	key[1] = 0xff;	key[2] = 0xe9;	key[3] = 0x92;
		key[4] = 0x86;	key[5] = 0x65;	key[6] = 0x73;	key[7] = 0x1c;
		key[8] = 0x6d;	key[9] = 0x6a;	key[10] = 0x8f;	key[11] = 0x94;
		key[12] = 0x67;	key[13] = 0x30;	key[14] = 0x83;	key[15] = 0x08;
		memcpy(desc->ad.key, key, 16);
		desc->ad.keysize = 16;
		memset(iv, 0, sizeof(iv));
		iv[0] = 0xca;	iv[1] = 0xfe;	iv[2] = 0xba;	iv[3] = 0xbe;
		iv[4] = 0xfa;	iv[5] = 0xce;	iv[6] = 0xdb;	iv[7] = 0xad;
		iv[8] = 0xde;	iv[9] = 0xca;	iv[10] = 0xf8;	iv[11] = 0x88;
		memcpy(desc->ad.iv, iv, 16);
	}
}

static int init_aead(struct generic_desc *desc,
		struct crypto_aead *tfm)
{
	u8 aes_128_gcm_ptext[] = "\xd9\x31\x32\x25\xf8\x84\x06\xe5"
				"\xa5\x59\x09\xc5\xaf\xf5\x26\x9a"
				"\x86\xa7\xa9\x53\x15\x34\xf7\xda"
				"\x2e\x4c\x30\x3d\x8a\x31\x8a\x72"
				"\x1c\x3c\x0c\x95\x95\x68\x09\x53"
				"\x2f\xcf\x0e\x24\x49\xa6\xb5\x25"
				"\xb1\x6a\xed\xf5\xaa\x0d\xe6\x57"
				"\xba\x63\x7b\x39\x1a\xaf\xd2\x55";
	u8 aes_128_gcm_ctext[] = "\x42\x83\x1e\xc2\x21\x77\x74\x24"
				"\x4b\x72\x21\xb7\x84\xd0\xd4\x9c"
				"\xe3\xaa\x21\x2f\x2c\x02\xa4\xe0"
				"\x35\xc1\x7e\x23\x29\xac\xa1\x2e"
				"\x21\xd5\x14\xb2\x54\x66\x93\x1c"
				"\x7d\x8f\x6a\x5a\xac\x84\xaa\x05"
				"\x1b\xa3\x0b\x39\x6a\x0a\xac\x97"
				"\x3d\x58\xe0\x91\x47\x3f\x59\x85"
				"\x4d\x5c\x2a\xf3\x27\xcd\x64\xa6"
				"\x2c\xf3\x5a\xbd\x2b\xa6\xfa\xb4";
	int src_size;
	size_t bsize;

	set_aead_key(desc);
	memset(desc->buf, 0, desc->len);
	bsize = crypto_aead_blocksize(tfm);
	if (!strcmp(desc->alg_name, "gcm(aes)") ||
		!strcmp(desc->alg_name, "gcm(sm4)")) {
		if (key_bits == 128) {
			if (desc->ad.encrypt_mode) {
				memcpy(desc->buf, aes_128_gcm_ptext, sizeof(aes_128_gcm_ptext));
				src_size = max(strlen(aes_128_gcm_ptext), bsize);
			} else {
				memcpy(desc->buf, aes_128_gcm_ctext, sizeof(aes_128_gcm_ctext));
				src_size = max(strlen(aes_128_gcm_ctext), bsize);
			}
		}
	}
	src_size = ALIGN(src_size, bsize);
	if (src_size > desc->len) {
		pr_err("Error. Source size (%d) exceeds limit (%d).\n",
			src_size, desc->len);
		return -EINVAL;
	}
	desc->len = src_size;
	desc->digest_len = desc->len;
	return 0;
}

static int test_aead(struct generic_desc *desc)
{
	struct crypto_aead *tfm = NULL;
	struct aead_request *req = NULL;
	struct scatterlist sg_src, sg_dst;
	int ret = -EINVAL;

	tfm = crypto_alloc_aead(desc->alg_name, 0, 0);
	if (IS_ERR(tfm)) {
		pr_err("Can't allocate AEAD %s (%ld)\n",
			alg_name, PTR_ERR(tfm));
		return PTR_ERR(tfm);
	}
	init_aead(desc, tfm);
	ret = crypto_aead_setkey(tfm, desc->ad.key, desc->ad.keysize);
	if (ret) {
		pr_err("Error on setting key: %d\n", ret);
		goto out;
	}

	req = aead_request_alloc(tfm, GFP_KERNEL);
	if (!req) {
		pr_err("Fail to allocate request for %s\n",
			alg_name);
		ret = -ENOMEM;
		goto out;
	}
	sg_init_one(&sg_src, desc->buf, desc->len);
	sg_init_one(&sg_dst, desc->digest, desc->digest_len);
	aead_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG |
				CRYPTO_TFM_REQ_MAY_SLEEP,
				crypto_req_done,
				&desc->ad.wait);
	aead_request_set_crypt(req, &sg_src, &sg_dst, desc->len, desc->ad.iv);
	pr_err("#%s, %d\n", __func__, __LINE__);
	if (desc->ad.encrypt_mode)
		ret = crypto_aead_encrypt(req);
	else
		ret = crypto_aead_decrypt(req);
	ret = crypto_wait_req(ret, &desc->ad.wait);
	if (ret) {
		pr_err("Error encrypt data: %d\n", ret);
		goto out_wait;
	}
	{
		pr_err("src:");
		dump_digest(desc->buf, desc->len);
		pr_err("dst:");
		dump_digest(desc->digest, desc->digest_len);
	}
	aead_request_free(req);
	crypto_free_aead(tfm);
	return 0;
out_wait:
	aead_request_free(req);
out:
	crypto_free_aead(tfm);
	return ret;
}

static int test_algm(struct generic_desc *desc)
{
	int ret = -EINVAL;

	if (desc->alg_type == ALG_SHASH)
		ret = test_shash(desc);
	else if (desc->alg_type == ALG_SKCIPHER)
		ret = test_skcipher(desc);
	else if (desc->alg_type == ALG_CIPHER)
		ret = test_cipher(desc);
	else if (desc->alg_type == ALG_AEAD)
		ret = test_aead(desc);
	return ret;
}

static struct generic_desc *alloc_generic_desc(int alg_type, char *alg_name)
{
	struct generic_desc *desc = NULL;
	void *data = NULL;

	data = kzalloc(buf_size, GFP_KERNEL);
	if (data == NULL) {
		pr_err("Fail to allocate data memory\n");
		return NULL;
	}

	desc = vzalloc(sizeof(struct generic_desc));
	if (desc == NULL)
		goto out;

	desc->buf = data;
	desc->len = buf_size;

	desc->alg_type = alg_type;
	desc->alg_name = kstrdup(alg_name, GFP_KERNEL);
	if (desc->alg_name == NULL)
		goto out_alg;

	desc->digest_len = desc->len;	// use source length first
	desc->digest = kzalloc(buf_size, GFP_KERNEL);
	if (desc->digest == NULL)
		goto out_dig;

	if (alg_type == ALG_SHASH) {
		// reserve large memory block
		desc->s.shash = vzalloc(PAGE_SIZE);
		if (desc->s.shash == NULL) {
			kfree(desc->digest);
			goto out_diverse;
		}
	} else if (alg_type == ALG_SKCIPHER) {
		get_random_bytes(data, buf_size);
		if (!strcmp(alg_name, "xts(aes)"))
			desc->sk.keysize = 64;
		else if (!strcmp(alg_name, "cbc(aes)") ||
			!strcmp(alg_name, "cbc(aes-generic)") ||
			!strcmp(alg_name, "cbc(aes-ce)") ||
			!strcmp(alg_name, "cbc-aes-ce") ||
			!strcmp(alg_name, "cbc-aes-neonbs"))
			desc->sk.keysize = 32;
		else if (!strcmp(alg_name, "ecb(aes)") ||
			!strcmp(alg_name, "ecb(aes-generic)") ||
			!strcmp(alg_name, "ecb(aes-ce)") ||
			!strcmp(alg_name, "ecb-aes-ce") ||
			!strcmp(alg_name, "ecb-aes-neonbs"))
			desc->sk.keysize = 32;
		else if (!strcmp(alg_name, "cbc-sm4-neon") ||
			!strcmp(alg_name, "cbc(sm4-generic)") ||
			!strcmp(alg_name, "cbc-sm4-ce") ||
			!strcmp(alg_name, "ecb-sm4-neon") ||
			!strcmp(alg_name, "ecb(sm4-generic)") ||
			!strcmp(alg_name, "ecb-sm4-ce") ||
			!strcmp(alg_name, "cbc(sm4)") ||
			!strcmp(alg_name, "ecb(sm4)"))
			desc->sk.keysize = 16;
		else
			desc->sk.keysize = 32;
		desc->sk.encrypt_mode = encrypt_mode;
	} else if (alg_type == ALG_CIPHER) {
		if (!strcmp(alg_name, "sm4") ||
			!strcmp(alg_name, "sm4-generic") ||
			!strcmp(alg_name, "sm4-ce"))
			desc->c.keysize = 16;
		desc->c.encrypt_mode = encrypt_mode;
	} else if (alg_type == ALG_AEAD) {
		desc->ad.encrypt_mode = encrypt_mode;
	} else
		goto out_diverse;
	return desc;

out_diverse:
	kfree(desc->digest);
out_dig:
	kfree(desc->alg_name);
out_alg:
	vfree(desc);
out:
	kfree(data);
	return NULL;
}

static void free_generic_desc(struct generic_desc *desc)
{
	if (desc->alg_type == ALG_SHASH) {
		vfree(desc->s.shash);
		kfree(desc->digest);
	} else if (desc->alg_type == ALG_SKCIPHER) {
	}
	kfree(desc->buf);
	vfree(desc);
}

static void skcipher_work_func(struct work_struct *work)
{
	int alg_type;

	struct generic_desc *desc = NULL;

	if (is_hash_alg(alg_name))
		alg_type = ALG_SHASH;
	else if (is_skcipher_alg(alg_name))
		alg_type = ALG_SKCIPHER;
	else if (is_cipher_alg(alg_name))
		alg_type = ALG_CIPHER;
	else if (is_aead_alg(alg_name))
		alg_type = ALG_AEAD;
	else {
		pr_err("Invalid algorithm: %s\n", alg_name);
		return;
	}

	desc = alloc_generic_desc(alg_type, alg_name);
	if (desc == NULL)
		return;

	if (!strcmp(mode_name, "perf"))
		run_algm(desc);
	else if (!strcmp(mode_name, "func"))
		test_algm(desc);
	else
		pr_err("Wrong mode: %s\n", mode_name);
	free_generic_desc(desc);
}

static DECLARE_WORK(skcipher_work, skcipher_work_func);

static int do_skcipher(void)
{
	hash_workqueue = create_workqueue("skcipher workqueue");
	if (!hash_workqueue) {
		pr_info("Fail to create workqueue.\n");
		return -ENOMEM;
	}

	queue_work(hash_workqueue, &skcipher_work);
	return 0;
}

static int __init hash_init(void)
{
	int ret;

	pr_info("Enter HASH module. ALG: %s, encrypt_mode: %d\n", alg_name, encrypt_mode);
	ret = crypto_has_alg(alg_name, 0, 0);
	if (!ret) {
		pr_warn("HASH algorithm %s does NOT exit.\n", alg_name);
		return -EINVAL;
	}
	if (buf_size <= 0) {
		pr_warn("Invalid buffer size (%d).\n", buf_size);
		return -EINVAL;
	}
	ret = do_skcipher();
	return ret;
}

static void __exit hash_exit(void)
{
	pr_info("Exit HASH module.\n");
	flush_workqueue(hash_workqueue);
	destroy_workqueue(hash_workqueue);
}

module_init(hash_init);
module_exit(hash_exit);
