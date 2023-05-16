#include <crypto/hash.h>
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
};

struct skcipher_desc {
	struct crypto_skcipher *tfm;
	struct skcipher_request *req;
	u8 key[64];
	u8 iv[16];
	int keysize;
};

enum {
	ALG_SHASH = 0,
	ALG_SKCIPHER,
};

struct generic_desc {
	union {
		struct sdesc		s;
		struct skcipher_desc	sk;
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

static char *mode_name = "perf";
module_param(mode_name, charp, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);

static struct workqueue_struct *hash_workqueue;

static void *buf = NULL;

static void dump_digest(unsigned char *digest, int digest_len)
{
	print_hex_dump(KERN_INFO, "Hash digest: ", DUMP_PREFIX_NONE, 32, 1,
			digest, digest_len, 0);
}

static int is_skcipher_alg(char *alg_name)
{
	if (!strcmp(alg_name, "xts(aes)"))
		return 1;
	if (!strcmp(alg_name, "cbc(aes)"))
		return 1;
	if (!strcmp(alg_name, "ecb(aes)"))
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
	if (!strcmp(alg_name, "sha256-generic"))
		return 1;
	if (!strcmp(alg_name, "sha512-generic"))
		return 1;
	if (!strcmp(alg_name, "chacha20-generic"))
		return 1;
	return 0;
}

static int run_shash(struct generic_desc *desc)
{
	struct crypto_shash *tfm = NULL;
	struct sdesc tmp;
	int i, ret, size;
	unsigned long alignmask;
	void *align_buf, *align_digest;

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
	crypto_shash_digest(desc->s.shash, align_buf, desc->len, align_digest);
	crypto_free_shash(tfm);
	return 0;
}

static int run_skcipher(struct generic_desc *desc)
{
	struct crypto_skcipher *tfm = NULL;
	struct skcipher_request *req = NULL;
	struct scatterlist sg;
	DECLARE_CRYPTO_WAIT(wait);
	u8 iv[16];	/* AES-256-XTS takes a 16-byte IV */
	u8 key[64];	/* AES-256-XTS takes a 64-byte key */
	int ret = -EINVAL;

	tfm = crypto_alloc_skcipher(alg_name, 0, 0);
	if (IS_ERR(tfm)) {
		pr_err("Can't allocate SKCIPHER %s (%ld)\n",
			alg_name, PTR_ERR(tfm));
		return PTR_ERR(tfm);
	}
	get_random_bytes(key, sizeof(key));
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
				      &wait);
	skcipher_request_set_crypt(req, &sg, &sg, desc->len, iv);
	ret = crypto_skcipher_encrypt(req);
	ret = crypto_wait_req(ret, &wait);
	if (ret) {
		pr_err("Error encrypt data: %d\n", ret);
		goto out_wait;
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

static int run_algm(struct generic_desc *desc)
{
	int ret = -EINVAL;

	if (desc->alg_type == ALG_SHASH)
		ret = run_shash(desc);
	else if (desc->alg_type == ALG_SKCIPHER)
		ret = run_skcipher(desc);
	return ret;
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
		ret = run_algm(desc);
		if (ret)
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

static int init_skcipher(struct generic_desc *desc,
			struct crypto_skcipher *tfm)
{
	u8 iv[16];	/* AES-256-XTS takes a 16-byte IV */
	u8 key[64];	/* AES-256-XTS takes a 64-byte key */
	u8 test_str[] = "Single block msg";
	int src_size, bsize;

	if (!strcmp(desc->alg_name, "cbc(aes)")) {
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
		memset(desc->buf, 0, desc->len);
		memcpy(desc->buf, test_str, sizeof(test_str));
	}
	bsize = crypto_skcipher_blocksize(tfm);
	src_size = max(strlen(test_str), bsize);
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
	ret = crypto_skcipher_encrypt(req);
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

static int test_algm(struct generic_desc *desc)
{
	int ret = -EINVAL;

	if (desc->alg_type == ALG_SHASH)
		pr_err("Need to implement testing SHASH function");
	else if (desc->alg_type == ALG_SKCIPHER)
		ret = test_skcipher(desc);
	return ret;
}

static struct generic_desc *alloc_generic_desc(int alg_type, char *alg_name)
{
	struct generic_desc *desc = NULL;
	void *data = NULL;
	int ret, digest_size;

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
		else if (!strcmp(alg_name, "cbc(aes)"))
			desc->sk.keysize = 32;
		else if (!strcmp(alg_name, "ecb(aes)"))
			desc->sk.keysize = 32;
		else
			desc->sk.keysize = 32;
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
		vfree(desc->digest);
	} else if (desc->alg_type == ALG_SKCIPHER) {
	}
	kfree(desc->buf);
	vfree(desc);
}

static void skcipher_work_func(struct work_struct *work)
{
	int ret, alg_type;

	struct generic_desc *desc = NULL;

	if (is_hash_alg(alg_name))
		alg_type = ALG_SHASH;
	else if (is_skcipher_alg(alg_name))
		alg_type = ALG_SKCIPHER;
	else {
		pr_err("Invalid algorithm: %s\n", alg_name);
		return;
	}

	desc = alloc_generic_desc(alg_type, alg_name);
	if (desc == NULL)
		return;

	if (!strcmp(mode_name, "perf"))
		measure_algm(desc);
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
