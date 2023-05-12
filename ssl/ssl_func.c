#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>

static unsigned char hello_str[] = "hello";

void md5_message(const unsigned char *message, size_t message_len,
		unsigned char **digest, unsigned int *digest_len)
{
	EVP_MD_CTX *mdctx;

	if ((mdctx = EVP_MD_CTX_new()) == NULL)
		return;

	if (1 != EVP_DigestInit_ex(mdctx, EVP_md5(), NULL))
		goto out;

	if (1 != EVP_DigestUpdate(mdctx, message, message_len))
		goto out;

	if ((*digest = (unsigned char *)OPENSSL_malloc(EVP_MD_size(EVP_md5()))) == NULL)
		goto out;

	if (1 != EVP_DigestFinal_ex(mdctx, *digest, digest_len))
		goto out;

out:
	EVP_MD_CTX_free(mdctx);
}

void dump_digest(unsigned char *digest, unsigned int digest_len)
{
	int i;

	printf("Digest:");
	for (i = 0; i < digest_len; i++)
		printf("%02x", digest[i]);
	printf("\n");
}

int main(void)
{
	unsigned char *digest = NULL;
	unsigned int digest_len;

	md5_message(hello_str, strlen(hello_str), &digest, &digest_len);
	dump_digest(digest, digest_len);
	return 0;
}
