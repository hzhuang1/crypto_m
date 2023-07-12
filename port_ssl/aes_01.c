#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "testvec.h"

#define OUT_BUF_LEN	4096

extern void aes_cbc_01(const unsigned char *inp, unsigned char *out,
			size_t length, const AES_KEY *key,
			unsigned char *ivp, const int enc);
extern void aes_v8_cbc_encrypt(const unsigned char *inp, unsigned char *out,
			       size_t length, const AES_KEY *key,
			       unsigned char *ivp, const int enc);

//#define aes_cbc		aes_v8_cbc_encrypt
#define aes_cbc		aes_cbc_01

#define U64(c)		c##ULL

typedef unsigned long long int u64;
typedef unsigned int u32;

typedef union {
    unsigned char b[8];
    u32 w[2];
    u64 d;
} uni;

static char *vec_out = NULL;

void init_buf(void)
{
	vec_out = calloc(1, OUT_BUF_LEN);
	if (!vec_out) {
		fprintf(stderr, "Fail to allocate buffer with %d bytes\n",
			OUT_BUF_LEN);
	}
}

void free_buf(void)
{
	free(vec_out);
}

void dump_buf(unsigned char *buf, int len)
{
	int i, j, cnt;

	cnt = len / 16;
	for (i = 0; i < cnt; i += 16) {
		printf("[0x%02x]: %02x %02x %02x %02x %02x %02x %02x %02x "
		       "%02x %02x %02x %02x %02x %02x %02x %02x\n",
		       i, buf[i], buf[i+1], buf[i+2], buf[i+3], buf[i+4],
		       buf[i+5], buf[i+6], buf[i+7], buf[i+8], buf[i+9],
		       buf[i+10], buf[i+11], buf[i+12], buf[i+13], buf[i+14],
		       buf[i+15]);
	}
	len = len - cnt * 16;
	if (len)
		printf("[0x%02x]:", i);
	for (j = 0; j < len; j++) {
		printf(" %02x", buf[i+j]);
	}
	printf("\n");
}


/*
 * Compute w := (w * x) mod (x^8 + x^4 + x^3 + x^1 + 1)
 * Therefore the name "xtime".
 */
static void XtimeWord(u32 *w)
{
    u32 a, b;

    a = *w;
    b = a & 0x80808080u;
    a ^= b;
    b -= b >> 7;
    b &= 0x1B1B1B1Bu;
    b ^= a << 1;
    *w = b;
}

static void XtimeLong(u64 *w)
{
    u64 a, b;

    a = *w;
    b = a & U64(0x8080808080808080);
    a ^= b;
    b -= b >> 7;
    b &= U64(0x1B1B1B1B1B1B1B1B);
    b ^= a << 1;
    *w = b;
}

static void SubLong(u64 *w)
{
    u64 x, y, a1, a2, a3, a4, a5, a6;

    x = *w;
    y = ((x & U64(0xFEFEFEFEFEFEFEFE)) >> 1) | ((x & U64(0x0101010101010101)) << 7);
    x &= U64(0xDDDDDDDDDDDDDDDD);
    x ^= y & U64(0x5757575757575757);
    y = ((y & U64(0xFEFEFEFEFEFEFEFE)) >> 1) | ((y & U64(0x0101010101010101)) << 7);
    x ^= y & U64(0x1C1C1C1C1C1C1C1C);
    y = ((y & U64(0xFEFEFEFEFEFEFEFE)) >> 1) | ((y & U64(0x0101010101010101)) << 7);
    x ^= y & U64(0x4A4A4A4A4A4A4A4A);
    y = ((y & U64(0xFEFEFEFEFEFEFEFE)) >> 1) | ((y & U64(0x0101010101010101)) << 7);
    x ^= y & U64(0x4242424242424242);
    y = ((y & U64(0xFEFEFEFEFEFEFEFE)) >> 1) | ((y & U64(0x0101010101010101)) << 7);
    x ^= y & U64(0x6464646464646464);
    y = ((y & U64(0xFEFEFEFEFEFEFEFE)) >> 1) | ((y & U64(0x0101010101010101)) << 7);
    x ^= y & U64(0xE0E0E0E0E0E0E0E0);
    a1 = x;
    a1 ^= (x & U64(0xF0F0F0F0F0F0F0F0)) >> 4;
    a2 = ((x & U64(0xCCCCCCCCCCCCCCCC)) >> 2) | ((x & U64(0x3333333333333333)) << 2);
    a3 = x & a1;
    a3 ^= (a3 & U64(0xAAAAAAAAAAAAAAAA)) >> 1;
    a3 ^= (((x << 1) & a1) ^ ((a1 << 1) & x)) & U64(0xAAAAAAAAAAAAAAAA);
    a4 = a2 & a1;
    a4 ^= (a4 & U64(0xAAAAAAAAAAAAAAAA)) >> 1;
    a4 ^= (((a2 << 1) & a1) ^ ((a1 << 1) & a2)) & U64(0xAAAAAAAAAAAAAAAA);
    a5 = (a3 & U64(0xCCCCCCCCCCCCCCCC)) >> 2;
    a3 ^= ((a4 << 2) ^ a4) & U64(0xCCCCCCCCCCCCCCCC);
    a4 = a5 & U64(0x2222222222222222);
    a4 |= a4 >> 1;
    a4 ^= (a5 << 1) & U64(0x2222222222222222);
    a3 ^= a4;
    a5 = a3 & U64(0xA0A0A0A0A0A0A0A0);
    a5 |= a5 >> 1;
    a5 ^= (a3 << 1) & U64(0xA0A0A0A0A0A0A0A0);
    a4 = a5 & U64(0xC0C0C0C0C0C0C0C0);
    a6 = a4 >> 2;
    a4 ^= (a5 << 2) & U64(0xC0C0C0C0C0C0C0C0);
    a5 = a6 & U64(0x2020202020202020);
    a5 |= a5 >> 1;
    a5 ^= (a6 << 1) & U64(0x2020202020202020);
    a4 |= a5;
    a3 ^= a4 >> 4;
    a3 &= U64(0x0F0F0F0F0F0F0F0F);
    a2 = a3;
    a2 ^= (a3 & U64(0x0C0C0C0C0C0C0C0C)) >> 2;
    a4 = a3 & a2;
    a4 ^= (a4 & U64(0x0A0A0A0A0A0A0A0A)) >> 1;
    a4 ^= (((a3 << 1) & a2) ^ ((a2 << 1) & a3)) & U64(0x0A0A0A0A0A0A0A0A);
    a5 = a4 & U64(0x0808080808080808);
    a5 |= a5 >> 1;
    a5 ^= (a4 << 1) & U64(0x0808080808080808);
    a4 ^= a5 >> 2;
    a4 &= U64(0x0303030303030303);
    a4 ^= (a4 & U64(0x0202020202020202)) >> 1;
    a4 |= a4 << 2;
    a3 = a2 & a4;
    a3 ^= (a3 & U64(0x0A0A0A0A0A0A0A0A)) >> 1;
    a3 ^= (((a2 << 1) & a4) ^ ((a4 << 1) & a2)) & U64(0x0A0A0A0A0A0A0A0A);
    a3 |= a3 << 4;
    a2 = ((a1 & U64(0xCCCCCCCCCCCCCCCC)) >> 2) | ((a1 & U64(0x3333333333333333)) << 2);
    x = a1 & a3;
    x ^= (x & U64(0xAAAAAAAAAAAAAAAA)) >> 1;
    x ^= (((a1 << 1) & a3) ^ ((a3 << 1) & a1)) & U64(0xAAAAAAAAAAAAAAAA);
    a4 = a2 & a3;
    a4 ^= (a4 & U64(0xAAAAAAAAAAAAAAAA)) >> 1;
    a4 ^= (((a2 << 1) & a3) ^ ((a3 << 1) & a2)) & U64(0xAAAAAAAAAAAAAAAA);
    a5 = (x & U64(0xCCCCCCCCCCCCCCCC)) >> 2;
    x ^= ((a4 << 2) ^ a4) & U64(0xCCCCCCCCCCCCCCCC);
    a4 = a5 & U64(0x2222222222222222);
    a4 |= a4 >> 1;
    a4 ^= (a5 << 1) & U64(0x2222222222222222);
    x ^= a4;
    y = ((x & U64(0xFEFEFEFEFEFEFEFE)) >> 1) | ((x & U64(0x0101010101010101)) << 7);
    x &= U64(0x3939393939393939);
    x ^= y & U64(0x3F3F3F3F3F3F3F3F);
    y = ((y & U64(0xFCFCFCFCFCFCFCFC)) >> 2) | ((y & U64(0x0303030303030303)) << 6);
    x ^= y & U64(0x9797979797979797);
    y = ((y & U64(0xFEFEFEFEFEFEFEFE)) >> 1) | ((y & U64(0x0101010101010101)) << 7);
    x ^= y & U64(0x9B9B9B9B9B9B9B9B);
    y = ((y & U64(0xFEFEFEFEFEFEFEFE)) >> 1) | ((y & U64(0x0101010101010101)) << 7);
    x ^= y & U64(0x3C3C3C3C3C3C3C3C);
    y = ((y & U64(0xFEFEFEFEFEFEFEFE)) >> 1) | ((y & U64(0x0101010101010101)) << 7);
    x ^= y & U64(0xDDDDDDDDDDDDDDDD);
    y = ((y & U64(0xFEFEFEFEFEFEFEFE)) >> 1) | ((y & U64(0x0101010101010101)) << 7);
    x ^= y & U64(0x7272727272727272);
    x ^= U64(0x6363636363636363);
    *w = x;
}

static void ShiftRows(u64 *state)
{
    unsigned char s[4];
    unsigned char *s0;
    int r;

    s0 = (unsigned char *)state;
    for (r = 0; r < 4; r++) {
        s[0] = s0[0*4 + r];
        s[1] = s0[1*4 + r];
        s[2] = s0[2*4 + r];
        s[3] = s0[3*4 + r];
        s0[0*4 + r] = s[(r+0) % 4];
        s0[1*4 + r] = s[(r+1) % 4];
        s0[2*4 + r] = s[(r+2) % 4];
        s0[3*4 + r] = s[(r+3) % 4];
    }
}

static void MixColumns(u64 *state)
{
    uni s1;
    uni s;
    int c;

    for (c = 0; c < 2; c++) {
        s1.d = state[c];
        s.d = s1.d;
        s.d ^= ((s.d & U64(0xFFFF0000FFFF0000)) >> 16)
               | ((s.d & U64(0x0000FFFF0000FFFF)) << 16);
        s.d ^= ((s.d & U64(0xFF00FF00FF00FF00)) >> 8)
               | ((s.d & U64(0x00FF00FF00FF00FF)) << 8);
        s.d ^= s1.d;
        XtimeLong(&s1.d);
        s.d ^= s1.d;
        s.b[0] ^= s1.b[1];
        s.b[1] ^= s1.b[2];
        s.b[2] ^= s1.b[3];
        s.b[3] ^= s1.b[0];
        s.b[4] ^= s1.b[5];
        s.b[5] ^= s1.b[6];
        s.b[6] ^= s1.b[7];
        s.b[7] ^= s1.b[4];
        state[c] = s.d;
    }
}

static void AddRoundKey(u64 *state, const u64 *w)
{
    state[0] ^= w[0];
    state[1] ^= w[1];
}

static void Cipher(const unsigned char *in, unsigned char *out,
                   const u64 *w, int nr)
{
    u64 state[2];
    int i;

    memcpy(state, in, 16);

    AddRoundKey(state, w);

    for (i = 1; i < nr; i++) {
        SubLong(&state[0]);
        SubLong(&state[1]);
        ShiftRows(state);
        MixColumns(state);
        AddRoundKey(state, w + i*2);
    }

    SubLong(&state[0]);
    SubLong(&state[1]);
    ShiftRows(state);
    AddRoundKey(state, w + nr*2);

    memcpy(out, state, 16);
}

/*
 * Encrypt a single block
 * in and out can overlap
 */
void AES_encrypt(const unsigned char *in, unsigned char *out,
                 const AES_KEY *key)
{
    const u64 *rk;

    assert(in && out && key);
    rk = (u64*)key->rd_key;

    Cipher(in, out, rk, key->rounds);
}

void t_cbc_01(void)
{
	struct cipher_testvec *vec = aes_cbc_tv_template;
	int cnt = ARRAY_SIZE(aes_cbc_tv_template);
	char iv[32];
	AES_KEY key;
	int i;

	init_buf();
	for (i = 3; i < 4; i++) {
		memset(iv, 0, 32);
		memcpy(iv, vec[i].iv, strlen(vec[i].iv));
		memcpy(key.rd_key, vec[i].key, vec[i].klen);
		key.rounds = vec[i].klen / 4 + 6;
		printf("key:\n");
		dump_buf(key.rd_key, vec[i].klen);
		printf("iv:\n");
		dump_buf(iv, 16);
		printf("ptext:\n");
		dump_buf(vec[i].ptext, vec[i].len);
		printf("klen:%d, rounds:%d\n", vec[i].klen, key.rounds);
		aes_cbc(vec[i].ptext, vec_out, vec[i].len, &key,
			iv, 1);
		printf("ctext:\n");
		dump_buf(vec_out, vec[i].len);
		printf("iv out:\n");
		dump_buf(iv, 16);
	}
	free_buf();
}

void t_cbc_02(void)
{
	struct cipher_testvec *vec = aes_cbc_tv_template;
	int cnt = ARRAY_SIZE(aes_cbc_tv_template);
	char iv[32];
	AES_KEY key;
	int i;

	init_buf();
	for (i = 3; i < 4; i++) {
		memset(iv, 0, 32);
		memcpy(iv, vec[i].iv, strlen(vec[i].iv));
		memcpy(key.rd_key, vec[i].key, vec[i].klen);
		key.rounds = vec[i].klen / 4 + 6;
		printf("key:\n");
		dump_buf(key.rd_key, vec[i].klen);
		printf("iv:\n");
		dump_buf(iv, 16);
		printf("ptext:\n");
		dump_buf(vec[i].ptext, vec[i].len);
		printf("klen:%d, rounds:%d\n", vec[i].klen, key.rounds);
		AES_encrypt(vec[i].ptext, vec_out, &key);
		printf("ctext:\n");
		dump_buf(vec_out, vec[i].len);
		printf("iv out:\n");
		dump_buf(iv, 16);
	}
	free_buf();
}

int main(void)
{
	t_cbc_01();
	t_cbc_02();
	return 0;
}
