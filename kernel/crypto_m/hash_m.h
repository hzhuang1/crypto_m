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
#include <linux/mm.h>
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

const struct aead_testvec aria_gcm_tv[] = {
	{
		.key	= "\xe9\x1e\x5e\x75\xda\x65\x55\x4a"
			  "\x48\x18\x1f\x38\x46\x34\x95\x62",
		.klen	= 16,
		.iv	= "\x00\x00\x20\xe8\xf5\xeb\x00\x00"
			  "\x00\x00\x31\x5e",
		.ivlen	= 12,
		.ptext	= "\xf5\x7a\xf5\xfd\x4a\xe1\x95\x62"
			  "\x97\x6e\xc5\x7a\x5a\x7a\xd5\x5a"
			  "\x5a\xf5\xc5\xe5\xc5\xfd\xf5\xc5"
			  "\x5a\xd5\x7a\x4a\x72\x72\xd5\x72"
			  "\x62\xe9\x72\x95\x66\xed\x66\xe9"
			  "\x7a\xc5\x4a\x4a\x5a\x7a\xd5\xe1"
			  "\x5a\xe5\xfd\xd5\xfd\x5a\xc5\xd5"
			  "\x6a\xe5\x6a\xd5\xc5\x72\xd5\x4a"
			  "\xe5\x4a\xc5\x5a\x95\x6a\xfd\x6a"
			  "\xed\x5a\x4a\xc5\x62\x95\x7a\x95"
			  "\x16\x99\x16\x91\xd5\x72\xfd\x14"
			  "\xe9\x7a\xe9\x62\xed\x7a\x9f\x4a"
			  "\x95\x5a\xf5\x72\xe1\x62\xf5\x7a"
			  "\x95\x66\x66\xe1\x7a\xe1\xf5\x4a"
			  "\x95\xf5\x66\xd5\x4a\x66\xe1\x6e"
			  "\x4a\xfd\x6a\x9f\x7a\xe1\xc5\xc5"
			  "\x5a\xe5\xd5\x6a\xfd\xe9\x16\xc5"
			  "\xe9\x4a\x6e\xc5\x66\x95\xe1\x4a"
			  "\xfd\xe1\x14\x84\x16\xe9\x4a\xd5"
			  "\x7a\xc5\x14\x6e\xd5\x9d\x1c\xc5",
		.plen	= 160,
		.assoc	= "\x80\x08\x31\x5e\xbf\x2e\x6f\xe0"
			  "\x20\xe8\xf5\xeb",
		.alen	= 12,
		.ctext	= "\x4d\x8a\x9a\x06\x75\x55\x0c\x70"
			  "\x4b\x17\xd8\xc9\xdd\xc8\x1a\x5c"
			  "\xd6\xf7\xda\x34\xf2\xfe\x1b\x3d"
			  "\xb7\xcb\x3d\xfb\x96\x97\x10\x2e"
			  "\xa0\xf3\xc1\xfc\x2d\xbc\x87\x3d"
			  "\x44\xbc\xee\xae\x8e\x44\x42\x97"
			  "\x4b\xa2\x1f\xf6\x78\x9d\x32\x72"
			  "\x61\x3f\xb9\x63\x1a\x7c\xf3\xf1"
			  "\x4b\xac\xbe\xb4\x21\x63\x3a\x90"
			  "\xff\xbe\x58\xc2\xfa\x6b\xdc\xa5"
			  "\x34\xf1\x0d\x0d\xe0\x50\x2c\xe1"
			  "\xd5\x31\xb6\x33\x6e\x58\x87\x82"
			  "\x78\x53\x1e\x5c\x22\xbc\x6c\x85"
			  "\xbb\xd7\x84\xd7\x8d\x9e\x68\x0a"
			  "\xa1\x90\x31\xaa\xf8\x91\x01\xd6"
			  "\x69\xd7\xa3\x96\x5c\x1f\x7e\x16"
			  "\x22\x9d\x74\x63\xe0\x53\x5f\x4e"
			  "\x25\x3f\x5d\x18\x18\x7d\x40\xb8"
			  "\xae\x0f\x56\x4b\xd9\x70\xb5\xe7"
			  "\xe2\xad\xfb\x21\x1e\x89\xa9\x53"
			  "\x5a\xba\xce\x3f\x37\xf5\xa7\x36"
			  "\xf4\xbe\x98\x4b\xbf\xfb\xed\xc1",
		.authsize = 16,
	}
};

const struct aead_testvec sm4_gcm_tv[] = {
	{
		.key	= "\x01\x23\x45\x67\x89\xAB\xCD\xEF"
			  "\xFE\xDC\xBA\x98\x76\x54\x32\x10",
		.klen   = 16,
		.iv     = "\x00\x00\x12\x34\x56\x78\x00\x00"
			  "\x00\x00\xAB\xCD",
		.ivlen	= 12,
		.ptext  = "\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA"
			  "\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB"
			  "\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC"
			  "\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"
			  "\xEE\xEE\xEE\xEE\xEE\xEE\xEE\xEE"
			  "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"
			  "\xEE\xEE\xEE\xEE\xEE\xEE\xEE\xEE"
			  "\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA",
		.plen   = 64,
		.assoc  = "\xFE\xED\xFA\xCE\xDE\xAD\xBE\xEF"
			  "\xFE\xED\xFA\xCE\xDE\xAD\xBE\xEF"
			  "\xAB\xAD\xDA\xD2",
		.alen   = 20,
		.ctext  = "\x17\xF3\x99\xF0\x8C\x67\xD5\xEE"
			  "\x19\xD0\xDC\x99\x69\xC4\xBB\x7D"
			  "\x5F\xD4\x6F\xD3\x75\x64\x89\x06"
			  "\x91\x57\xB2\x82\xBB\x20\x07\x35"
			  "\xD8\x27\x10\xCA\x5C\x22\xF0\xCC"
			  "\xFA\x7C\xBF\x93\xD4\x96\xAC\x15"
			  "\xA5\x68\x34\xCB\xCF\x98\xC3\x97"
			  "\xB4\x02\x4A\x26\x91\x23\x3B\x8D"
			  "\x83\xDE\x35\x41\xE4\xC2\xB5\x81"
			  "\x77\xE0\x65\xA9\xBF\x7B\x62\xEC",
		.authsize = 16,
	}
};
#endif	// __HASH_M_HEADER__
