#include <stdint.h>
#include <stdio.h>

extern int dump_cntw(void);
extern void load_01(unsigned char *buf);
extern void load_02(unsigned char *in, unsigned char *out);
extern void rev_01(unsigned char *in, unsigned char *out);
extern void rtl32_01(unsigned char *in, unsigned char *out);
extern void round32_01(unsigned char *in, unsigned char *out);
extern void round32_02(unsigned char *seed, unsigned char *in);

unsigned char in[1024], out[1024];

void set_buf(unsigned char *buf, unsigned char val, size_t len)
{
	for (int i = 0; i < len; i++)
		buf[i] = val;
}

void clear_buf(unsigned char *buf, size_t len)
{
	for (int i = 0; i < len; i++)
		buf[i] = 0;
}

void init_buf(unsigned char *buf, unsigned char val, size_t len)
{
	for (int i = 0; i < len; i++) {
		buf[i] = val + ((i / 8) * 0x10) + (i % 8);
	}
}

void dump_buf(unsigned char *buf, size_t len)
{
	int i;

	for (i = 0; i < len; i += 16) {
		printf("[0x%x]: %02x-%02x-%02x-%02x %02x-%02x-%02x-%02x "
			"%02x-%02x-%02x-%02x %02x-%02x-%02x-%02x\n",
			i, buf[i], buf[i + 1], buf[i + 2], buf[i + 3],
			buf[i + 4], buf[i + 5], buf[i + 6], buf[i + 7],
			buf[i + 8], buf[i + 9], buf[i + 10], buf[i + 11],
			buf[i + 12], buf[i + 13], buf[i + 14], buf[i + 15]);
	}
}

/* Call LD1W instruction (vector index) to gather load data. */
void t_load_01(void)
{
	int cntw;

	cntw = dump_cntw();
	printf("cntw:%d\n", cntw);
	set_buf(in, 0xaa, 256);
	init_buf(out, 0x55, 256);
	/* index is stored in Z0 now */
	load_01(out);
	dump_buf(out, 256);
	load_02(in, out);
	dump_buf(out, 256);
}

/* Call REVH instruction to reverse two 32-bit fields in each 64-bit field. */
void t_rev_01(void)
{
	init_buf(in, 0x37, 256);
	init_buf(out, 0x55, 256);
	rev_01(in, out);
	dump_buf(out, 256);
}

void t_rtl_01(void)
{
	init_buf(in, 0x37, 256);
	init_buf(out, 0x55, 256);
	dump_buf(in, 64);
	rtl32_01(in, out);
	dump_buf(out, 64);
}

void t_round_01(void)
{
	init_buf(in, 0x37, 256);
	init_buf(out, 0x55, 256);
	dump_buf(in, 64);
	// out works as seed
	round32_01(out, in);
	dump_buf(out, 64);
}

void t_round_02(void)
{
	uint32_t seed, cntw;
	uint32_t *pseed, *pin;

	init_buf(in, 0x37, 1024);
	init_buf(out, 0x55, 1024);
	dump_buf(in, 64);
	round32_02(out, in);
	dump_buf(out, 1024);
}

#define xxh_rotl32(x, r) ((x << r) | (x >> (32 - r)))

static const uint32_t PRIME32_1 = 2654435761U;
static const uint32_t PRIME32_2 = 2246822519U;
static const uint32_t PRIME32_3 = 3266489917U;
static const uint32_t PRIME32_4 =  668265263U;
static const uint32_t PRIME32_5 =  374761393U;

uint32_t xxh32_round(uint32_t seed, const uint32_t input)
{
	seed += input * PRIME32_2;
	seed = xxh_rotl32(seed, 13);
	seed *= PRIME32_1;
	return seed;
}

// only one seed
void sample_round_01(void)
{
	uint32_t seed, cntw;
	uint32_t *pseed, *pin;

	init_buf(in, 0x37, 1024);
	init_buf(out, 0x55, 1024);
	dump_buf(in, 64);
	pseed = (uint32_t *)out;
	pin = (uint32_t *)in;
	// 512 / 32 = 16
	cntw = dump_cntw();
	for (int i = 0; i < cntw; i++) {
		seed = xxh32_round(*pseed, *(const uint32_t *)pin);
		*pseed = seed;
		pseed++;
		pin++;
	}
	printf("seed=0x%x\n", seed);
	dump_buf(out, 64);
}

// There're 16 seeds in the seed buffer.
void sample_round_02(void)
{
	uint32_t seed, cntw;
	uint32_t *pseed, *pin;

	init_buf(in, 0x37, 1024);
	init_buf(out, 0x55, 1024);
	dump_buf(in, 64);
	pseed = (uint32_t *)out;
	pin = (uint32_t *)in;
	// 512 / 32 = 16
	cntw = dump_cntw();
	for (int i = 0; i < cntw * 16; i++) {
		seed = xxh32_round(*pseed, *(const uint32_t *)pin);
		*pseed = seed;
		pin++;
		pseed++;
	}
	printf("seed=0x%x\n", seed);
	dump_buf(out, 1024);
}

int main(void)
{
	t_round_02();
	sample_round_02();
	return 0;
}
