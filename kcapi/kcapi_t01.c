#include <errno.h>
#include <kcapi.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>

#define MD5_DIGEST_LEN	16
#define TEST_STRING	"hello"

void dump_digest(uint8_t *buf, size_t len)
{
	size_t i;

	printf("%s, len:%ld\n", __func__, len);
	if (len == 0)
		return;

	printf("Digest:");
	for (i = 0; i < len - 1; i++) {
		printf("%02x-", buf[i]);
	}
	printf("%02x\n", buf[i]);
}

#if 0
int ssl_md5_01(unsigned char *buf, size_t len)
{
	// OPENSSL 1.x
	MD5_CTX *c;
	int ret, i;
	unsigned char md[MD5_DIGEST_LENGTH];

	ret = MD5_Init(c);
	if (ret < 0) {
		printf("MD5_Init: (%d)\n", ret);
		return ret;
	}
	ret = MD5_Update(c, (const void *)buf, len);
	if (ret < 0) {
		printf("MD5_Update: (%d)\n", ret);
		return ret;
	}
	ret = MD5_Final(&md, c);
	if (ret < 0) {
		printf("MD5_Final: (%d)\n", ret);
		return ret;
	}
	dump_digest(md, MD5_DIGEST_LENGTH);
	return 0;
}
#endif

//#define SSL_ALLOC_MEM		1
int ssl_md5_02(unsigned char *buf, size_t len, unsigned char *digest)
{
	// OPENSSL 3.0
	EVP_MD_CTX *md_ctx;
#ifdef SSL_ALLOC_MEM
	unsigned char *digest;
#endif
	unsigned int digest_len;
	int ret;

	md_ctx = EVP_MD_CTX_new();
	if (md_ctx == NULL) {
		printf("Fail to create MD_CTX.\n");
		ret = -ENOMEM;
		goto out;
	}
#ifdef SSL_ALLOC_MEM
	digest = OPENSSL_malloc(EVP_MD_size(EVP_md5()));
	if (digest == NULL) {
		printf("Fail to allocate memory.\n");
		ret = -ENOMEM;
		goto out_dig;
	}
#endif
	ret = EVP_DigestInit_ex(md_ctx, EVP_md5(), NULL);
	if (ret != 1) {
		printf("Fail to init MD5.\n");
		ret = -EFAULT;
		goto out_init;
	}
	ret = EVP_DigestUpdate(md_ctx, buf, len);
	if (ret != 1) {
		printf("Fail to calculate MD5.\n");
		ret = -EINVAL;
		goto out_init;
	}
	ret = EVP_DigestFinal_ex(md_ctx, digest, &digest_len);
	if (ret != 1) {
		printf("Fail to get MD5 digest.\n");
		ret = -EFAULT;
		goto out_init;
	}
	dump_digest(digest, digest_len);
#ifdef SSL_ALLOC_MEM
	OPENSSL_free(digest);
#endif
	EVP_MD_CTX_free(md_ctx);
	return 0;
out_init:
#ifdef SSL_ALLOC_MEM
	OPENSSL_free(digest);
out_dig:
#endif
	EVP_MD_CTX_free(md_ctx);
out:
	return ret;
}

int k_md_01(unsigned char *buf, size_t len)
{
	struct kcapi_handle *handle;
	int ret, i;
	ssize_t rc;
	uint8_t md[MD5_DIGEST_LEN << 1];

	memset(&md, 0, MD5_DIGEST_LEN << 1);
	ret = kcapi_md_init(&handle, "md5", 0);
	if (ret) {
		printf("Allocation of hash md5 failed (%d)\n", ret);
		return ret;
	}

	rc = kcapi_md_update(handle, buf, len);
	if (rc < 0) {
		printf("Hash update of buffer failed (%ld)\n", rc);
		kcapi_md_destroy(handle);
		return -EINVAL;
	}

	rc = kcapi_md_final(handle, (uint8_t *)&md, MD5_DIGEST_LEN);
	printf("rc:%ld\n", rc);
	dump_digest(md, MD5_DIGEST_LEN);
	kcapi_md_destroy(handle);
	return 0;
}

int main(void)
{
	unsigned char *digest;

	digest = malloc(MD5_DIGEST_LEN);
	if (digest == NULL) {
		printf("Fail to allocate memory!\n");
		return -ENOMEM;
	}
	k_md_01(TEST_STRING, strlen(TEST_STRING));
	ssl_md5_02(TEST_STRING, strlen(TEST_STRING), digest);
	free(digest);
	return 0;
}
