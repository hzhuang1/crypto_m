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

#define MEASURE_COUNT	1000

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
	memcpy(&tmp, &desc->s, sizeof(struct sdesc));
	for (i = 0; i < MEASURE_COUNT; i++) {
		crypto_shash_digest(desc->s.shash, align_buf, desc->len, align_digest);
		memcpy(&desc->s, &tmp, sizeof(struct sdesc));
	}
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
	ret = crypto_skcipher_setkey(tfm, key, sizeof(key));
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
		count += MEASURE_COUNT;
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

static struct generic_desc *alloc_generic_desc(int alg_type, char *alg_name)
{
	struct generic_desc *desc = NULL;
	void *data = NULL;
	int ret;

	data = kzalloc(buf_size + 63, GFP_KERNEL);
	if (data == NULL) {
		pr_err("Fail to allocate data memory\n");
		return NULL;
	}

	desc = vzalloc(sizeof(struct generic_desc));
	if (desc == NULL)
		goto out;

	desc->buf = data;
	desc->len = buf_size;

	if (alg_type == ALG_SHASH) {
		// reserve large memory block
		desc->digest = vzalloc(512);
		if (desc->digest == NULL) {
			vfree(desc);
			goto out;
		}
		desc->s.shash = vzalloc(PAGE_SIZE);
		if (desc->s.shash == NULL) {
			vfree(desc->digest);
			vfree(desc);
			goto out;
		}
	} else if (alg_type == ALG_SKCIPHER) {
		get_random_bytes(data, buf_size);
	} else
		goto out;
	desc->alg_type = alg_type;
	return desc;

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

#if 0
static void *init_skcipher_data(void)
{
	u8 *data = NULL;

	/* Prepare the input data */
	data = kzalloc(buf_size, GFP_KERNEL);
	if (!data) {
		pr_err("Fail to allocate memory\n");
		return NULL;
	}
	get_random_bytes(data, buf_size);
	return data;
}
#endif

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

	measure_algm(desc);
	free_generic_desc(desc);
}

static DECLARE_WORK(measure_skcipher_work, skcipher_work_func);

static int do_skcipher(void)
{
	hash_workqueue = create_workqueue("skcipher workqueue");
	if (!hash_workqueue) {
		pr_info("Fail to create workqueue.\n");
		return -ENOMEM;
	}

	queue_work(hash_workqueue, &measure_skcipher_work);
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
