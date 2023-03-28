#include <crypto/hash.h>
#include <linux/crypto.h>
#include <linux/err.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/scatterlist.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Haojian Zhuang");
MODULE_DESCRIPTION("A simple module for crypto.");
MODULE_VERSION("0.1");

// The default hash algorithm is MD5.
static char *hash_name = "md5-generic";
// charp means char pointer
module_param(hash_name, charp, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
//MODULE_PARAM_DESC(hash_name, "Run the hash algorithm.");

static int buf_size = PAGE_SIZE;
module_param(buf_size, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);

struct sdesc {
	struct shash_desc shash;
	void *buf;
	int len;
};

static struct sdesc *init_sdesc(struct crypto_shash *alg)
{
	struct sdesc *sdesc;
	int size;

	size = sizeof(struct shash_desc) + crypto_shash_descsize(alg);
	sdesc = kmalloc(size, GFP_KERNEL);
	if (!sdesc) {
		pr_info("Fail to allocate SHASH desc.\n");
		return ERR_PTR(-ENOMEM);
	}
	sdesc->shash.tfm = alg;
	return sdesc;
}

static int init_data(struct sdesc *sdesc)
{
	int i;
	unsigned char tmp;

	if (!sdesc)
		return -EINVAL;
	sdesc->len = buf_size;
	sdesc->buf = vmalloc(buf_size);
	if (!sdesc->buf) {
		pr_warn("Fail to allocate buffer.\n");
		return PTR_ERR(sdesc->buf);
	}
	for (i = 0; i < (buf_size + PAGE_SIZE - 1) >> PAGE_SHIFT; i++) {
		tmp = *((unsigned char *)sdesc->buf + (i << PAGE_SHIFT));
	}
	return 0;
}

static int test_hello(struct sdesc *sdesc)
{
	unsigned char test_buf[] = "hello";
	int len;

	if (!sdesc)
		return -EINVAL;
	len = strlen(test_buf);
	if (len == 0)
		return -EINVAL;
	memcpy(sdesc->buf, test_buf, len);
	sdesc->len = len;
	return 0;
}

static int do_shash(unsigned char *digest)
{
	struct crypto_shash *alg;
	struct sdesc *sdesc;
	int ret = 0;

	alg = crypto_alloc_shash(hash_name, 0, 0);
	if (IS_ERR(alg)) {
		pr_info("Can't allocate SHASH %s\n", hash_name);
		return PTR_ERR(alg);
	}
	sdesc = init_sdesc(alg);
	if (IS_ERR(sdesc)) {
		ret = PTR_ERR(sdesc);
		goto out;
	}
	ret = init_data(sdesc);
	if (ret)
		goto out_data;
	test_hello(sdesc);
	ret = crypto_shash_digest(&sdesc->shash, sdesc->buf, sdesc->len, digest);
	vfree(sdesc->buf);
out_data:
	kfree(sdesc);
out:
	crypto_free_shash(alg);
	return ret;
}

static void dump_digest(unsigned char *digest)
{
	int digest_len;

	if (!strcmp(hash_name, "md5-generic") || !strcmp(hash_name, "md5")) {
		digest_len = 16;
	} else if (!strcmp(hash_name, "xxhash64-generic")
		|| !strcmp(hash_name, "xxhash64")) {
	}
	print_hex_dump(KERN_INFO, "Hash digest: ", DUMP_PREFIX_NONE, 32, 1,
			digest, digest_len, 0);
}

static int __init hash_init(void)
{
	int ret;
	unsigned char digest[256] = {0};

	ret = crypto_has_alg(hash_name, 0, 0);
	if (!ret) {
		pr_warn("HASH algorithm %s does NOT exit.\n", hash_name);
		return -EINVAL;
	}
	if (buf_size <= 0) {
		pr_warn("Invalid buffer size (%d).\n", buf_size);
		return -EINVAL;
	}
	pr_info("HASH algorithm: %s. Data size: %d\n", hash_name, buf_size);

	ret = do_shash(digest);
	dump_digest(digest);
	return ret;
}

static void __exit hash_exit(void)
{
	pr_info("Exit HASH module.\n");
}

module_init(hash_init);
module_exit(hash_exit);
