#ifndef __HASH_M_HEADER__

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


#define AES_GCM_TAG_SIZE	16

//#define ARRAY_SIZE(x)	(sizeof(x) / sizeof((x)[0]))

struct aead_testvec {
	const char *key;
	const char *iv;
	const char *ptext;
	const char *assoc;
	const char *ctext;	// ctext + authsize
	unsigned int klen;	// key length
	unsigned int ivlen;	// iv length
	unsigned int plen;	// ptext/ctext length
	unsigned int alen;	// assoc length
	unsigned int authsize;	// ctext length = ptext length + authsize
	int setkey_error;
	int setauthsize_error;
	int crypt_error;
};

const struct aead_testvec aes_gcm_tv[] = {
	{
		.key	= "\x00\x00\x00\x00\x00\x00\x00\x00"
			  "\x00\x00\x00\x00\x00\x00\x00\x00",
		.klen	= 16,
		.ptext	= "\x00\x00\x00\x00\x00\x00\x00\x00"
			  "\x00\x00\x00\x00\x00\x00\x00\x00",
		.plen	= 16,
		.alen	= 0,
		.ctext	= "\x03\x88\xda\xce\x60\xb6\xa3\x92"
			  "\xf3\x28\xc2\xb9\x71\xb2\xfe\x78"
			  "\xab\x6e\x47\xd4\x2c\xec\x13\xbd"
			  "\xf5\x3a\x67\xb2\x12\x57\xbd\xdf",
		.authsize = 16,
	}, {
		.key	= "\xfe\xff\xe9\x92\x86\x65\x73\x1c"
			  "\x6d\x6a\x8f\x94\x67\x30\x83\x08",
		.klen	= 16,
		.iv	= "\xca\xfe\xba\xbe\xfa\xce\xdb\xad"
			  "\xde\xca\xf8\x88",
		.ivlen	= 12,
		.ptext	= "\xd9\x31\x32\x25\xf8\x84\x06\xe5"
			  "\xa5\x59\x09\xc5\xaf\xf5\x26\x9a"
			  "\x86\xa7\xa9\x53\x15\x34\xf7\xda"
			  "\x2e\x4c\x30\x3d\x8a\x31\x8a\x72"
			  "\x1c\x3c\x0c\x95\x95\x68\x09\x53"
			  "\x2f\xcf\x0e\x24\x49\xa6\xb5\x25"
			  "\xb1\x6a\xed\xf5\xaa\x0d\xe6\x57"
			  "\xba\x63\x7b\x39\x1a\xaf\xd2\x55",
		.plen	= 64,
		.alen	= 0,
		.ctext	= "\x42\x83\x1e\xc2\x21\x77\x74\x24"
			  "\x4b\x72\x21\xb7\x84\xd0\xd4\x9c"
			  "\xe3\xaa\x21\x2f\x2c\x02\xa4\xe0"
			  "\x35\xc1\x7e\x23\x29\xac\xa1\x2e"
			  "\x21\xd5\x14\xb2\x54\x66\x93\x1c"
			  "\x7d\x8f\x6a\x5a\xac\x84\xaa\x05"
			  "\x1b\xa3\x0b\x39\x6a\x0a\xac\x97"
			  "\x3d\x58\xe0\x91\x47\x3f\x59\x85"
			  "\x4d\x5c\x2a\xf3\x27\xcd\x64\xa6"
			  "\x2c\xf3\x5a\xbd\x2b\xa6\xfa\xb4",
		.authsize = 16,
	}, {
		.key	= "\xfe\xff\xe9\x92\x86\x65\x73\x1c"
			  "\x6d\x6a\x8f\x94\x67\x30\x83\x08",
		.klen	= 16,
		.iv	= "\xca\xfe\xba\xbe\xfa\xce\xdb\xad"
			  "\xde\xca\xf8\x88",
		.ivlen	= 12,
		.ptext	= "\xd9\x31\x32\x25\xf8\x84\x06\xe5"
			  "\xa5\x59\x09\xc5\xaf\xf5\x26\x9a"
			  "\x86\xa7\xa9\x53\x15\x34\xf7\xda"
			  "\x2e\x4c\x30\x3d\x8a\x31\x8a\x72"
			  "\x1c\x3c\x0c\x95\x95\x68\x09\x53"
			  "\x2f\xcf\x0e\x24\x49\xa6\xb5\x25"
			  "\xb1\x6a\xed\xf5\xaa\x0d\xe6\x57"
			  "\xba\x63\x7b\x39",
		.plen	= 60,
		.assoc	= "\xfe\xed\xfa\xce\xde\xad\xbe\xef"
			  "\xfe\xed\xfa\xce\xde\xad\xbe\xef"
			  "\xab\xad\xda\xd2",
		.alen	= 20,
		.ctext	= "\x42\x83\x1e\xc2\x21\x77\x74\x24"
			  "\x4b\x72\x21\xb7\x84\xd0\xd4\x9c"
			  "\xe3\xaa\x21\x2f\x2c\x02\xa4\xe0"
			  "\x35\xc1\x7e\x23\x29\xac\xa1\x2e"
			  "\x21\xd5\x14\xb2\x54\x66\x93\x1c"
			  "\x7d\x8f\x6a\x5a\xac\x84\xaa\x05"
			  "\x1b\xa3\x0b\x39\x6a\x0a\xac\x97"
			  "\x3d\x58\xe0\x91"
			  "\x5b\xc9\x4f\xbc\x32\x21\xa5\xdb"
			  "\x94\xfa\xe9\x5a\xe7\x12\x1a\x47",
		.authsize = 16,
	}, {
		.key	= "\x00\x00\x00\x00\x00\x00\x00\x00"
			  "\x00\x00\x00\x00\x00\x00\x00\x00"
			  "\x00\x00\x00\x00\x00\x00\x00\x00",
		.klen	= 24,
		.ptext	= "\x00\x00\x00\x00\x00\x00\x00\x00"
			  "\x00\x00\x00\x00\x00\x00\x00\x00",
		.plen	= 16,
		.alen	= 0,
		.ctext	= "\x98\xe7\x24\x7c\x07\xf0\xfe\x41"
			  "\x1c\x26\x7e\x43\x84\xb0\xf6\x00"
			  "\x2f\xf5\x8d\x80\x03\x39\x27\xab"
			  "\x8e\xf4\xd4\x58\x75\x14\xf0\xfb",
		.authsize = 16,
	}, {
		.key	= "\xfe\xff\xe9\x92\x86\x65\x73\x1c"
			  "\x6d\x6a\x8f\x94\x67\x30\x83\x08"
			  "\xfe\xff\xe9\x92\x86\x65\x73\x1c",
		.klen	= 24,
		.iv	= "\xca\xfe\xba\xbe\xfa\xce\xdb\xad"
			  "\xde\xca\xf8\x88",
		.ivlen	= 12,
		.ptext	= "\xd9\x31\x32\x25\xf8\x84\x06\xe5"
			  "\xa5\x59\x09\xc5\xaf\xf5\x26\x9a"
			  "\x86\xa7\xa9\x53\x15\x34\xf7\xda"
			  "\x2e\x4c\x30\x3d\x8a\x31\x8a\x72"
			  "\x1c\x3c\x0c\x95\x95\x68\x09\x53"
			  "\x2f\xcf\x0e\x24\x49\xa6\xb5\x25"
			  "\xb1\x6a\xed\xf5\xaa\x0d\xe6\x57"
			  "\xba\x63\x7b\x39\x1a\xaf\xd2\xff",
		.plen	= 64,
		.ctext	= "\x39\x80\xca\x0b\x3c\x00\xe8\x41"
			  "\xeb\x06\xfa\xc4\x87\x2a\x27\x57"
			  "\x85\x9e\x1c\xea\xa6\xef\xd9\x84"
			  "\x62\x85\x93\xb4\x0c\xa1\xe1\x9c"
			  "\x7d\x77\x3d\x00\xc1\x44\xc5\x25"
			  "\xac\x61\x9d\x18\xc8\x4a\x3f\x47"
			  "\x18\xe2\x44\x8b\x2f\xe3\x24\xd9"
			  "\xcc\xda\x27\x10\xac\xad\xe2\x56"
			  "\x99\x24\xa7\xc8\x58\x73\x36\xbf"
			  "\xb1\x18\x02\x4d\xb8\x67\x4a\x14",
		.authsize = 16,
	}
};

#endif	// __HASH_M_HEADER__