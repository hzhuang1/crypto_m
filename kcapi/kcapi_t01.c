#include <errno.h>
#include <fcntl.h>
#include <kcapi.h>
#include <openssl/evp.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/uio.h>

#define MD5_DIGEST_LEN	16
#define TEST_STRING	"hello"

void dump_digest(uint8_t *buf, size_t len)
{
	size_t i;

	if (len == 0)
		return;

	printf("Digest:");
	for (i = 0; i < len - 1; i++) {
		printf("%02x-", buf[i]);
	}
	printf("%02x\n", buf[i]);
}

int cmp_digest(uint8_t *d1, uint8_t *d2, size_t len)
{
	int i;

	if ((d1 == NULL) || (d2 == NULL) || (len == 0))
		return -EINVAL;

	for (i = 0; i < len; i++) {
		if (d1[i] != d2[i]) {
			printf("Digests are not matched.\n");
			printf("#1:");
			dump_digest(d1, i);
			printf("#2:");
			dump_digest(d2, i);
			return -EINVAL;
		}
	}
	return 0;
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

	if (!digest) {
		printf("%s: digest is empty.\n", __func__);
		return -EINVAL;
	}

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

int k_md_01(unsigned char *buf, size_t len, unsigned char *digest)
{
	struct kcapi_handle *handle;
	int ret, i;
	ssize_t rc;
	uint8_t md[MD5_DIGEST_LEN << 1];

	if (!digest) {
		printf("%s: digest is empty.\n", __func__);
		return -EINVAL;
	}

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

	rc = kcapi_md_final(handle, (uint8_t *)digest, MD5_DIGEST_LEN);
	if (rc != MD5_DIGEST_LEN) {
		printf("rc (%ld) is wrong\n", rc);
		kcapi_md_destroy(handle);
		return -EINVAL;
	}
	kcapi_md_destroy(handle);
	return 0;
}

int case_01(void)
{
	unsigned char d1[MD5_DIGEST_LEN], d2[MD5_DIGEST_LEN];
	int ret;

	k_md_01(TEST_STRING, strlen(TEST_STRING), d1);
	ssl_md5_02(TEST_STRING, strlen(TEST_STRING), d2);
	ret = cmp_digest(d1, d2, MD5_DIGEST_LEN);
	if (ret < 0)
		return ret;
	printf("Digests are matched. ");
	dump_digest(d1, MD5_DIGEST_LEN);
	return 0;
}

int case_02(void)
{
	unsigned char d1[MD5_DIGEST_LEN], d2[MD5_DIGEST_LEN];
	unsigned char *buf;
	int ret;
	int fd;
	size_t len = 8193;
	ssize_t sz;

	buf = malloc(len);
	if (buf == NULL)
		return -ENOMEM;
	fd = open("/dev/random", O_RDONLY);
	if (fd < 0) {
		printf("Fail to open random file!\n");
		ret = -EINVAL;
		goto out;
	}
	memset(buf, 0, len);
	sz = read(fd, buf, len);
	if (sz < (ssize_t)len) {
		printf("Too less data is read (%ld).\n", sz);
		ret = -EINVAL;
		goto out_rd;
	}
	k_md_01(buf, len, d1);
	ssl_md5_02(buf, len, d2);
	ret = cmp_digest(d1, d2, MD5_DIGEST_LEN);
	if (ret < 0)
		goto out_rd;
	printf("Digests are matched. ");
	dump_digest(d1, MD5_DIGEST_LEN);
	close(fd);
	free(buf);
	return 0;
out_rd:
	close(fd);
out:
	free(buf);
	return ret;
}

int main(void)
{
	case_01();
	case_02();
	return 0;
}
