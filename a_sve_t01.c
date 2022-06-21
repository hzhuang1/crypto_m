#include <stdint.h>
#include <stdio.h>

extern int dump_cntw(void);
extern void load_01(unsigned char *buf);
extern void load_02(unsigned char *in, unsigned char *out);
extern void rev_01(unsigned char *in, unsigned char *out);
extern void rtl32_01(unsigned char *in, unsigned char *out);
extern void round32_01(unsigned char *in, unsigned char *out);
extern void round32_02(unsigned char *seed, unsigned char *in);
extern void round32_03(unsigned char *seed, unsigned char *in);

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

/*
 * Z3.s0 means the lowest 32-bit in Z3 register
 * SEED buffer:
 * SVE512: 16 jobs = 256 bytes	(SVE2048: 64 jobs = 1024 bytes)
 * JOB0 0x00:	V1	V2	V3	V4
 * 		Z3.s0	Z4.s0	Z5.s0	Z6.s0
 * JOB1 0x10:	V1	V2	V3	V4
 *		Z3.s1	Z4.s1	Z5.s1	Z6.s1
 * ...
 * JOB15 0xf0:	V1	V2	V3	V4
 *		Z3.s15	Z4.s15	Z5.s15	Z6.s15
 * IN buffer:
 * SVE512: 512 / 32 = 16
 * There's only one block for each job. Each block is 64-byte.
 * And each job operates 4 data only.
 * 16 jobs means 1024-byte.
 * JOB0 0x000:	Z7.s0	Z8.s0	Z9.s0	Z10.s0
 *      0x010:	Z7.s0	Z8.s0	Z9.s0	Z10.s0
 * ...
 *      0x030:	Z7.s0	Z8.s0	Z9.s0	Z10.s0
 * JOB1 0x040:	Z7.s1	Z8.s1	Z9.s1	Z10.s1
 * ...
 * JOB15 0x3c0:	Z7.s15	Z8.s15	Z9.s15	Z10.s15
 * ...
 */
void t_round_03(void)
{
	uint32_t seed, cntw;
	uint32_t *pseed, *pin;

	init_buf(in, 0x37, 1024);
	init_buf(out, 0x55, 1024);
	dump_buf(in, 256);
	round32_03(out, in);
	dump_buf(out, 256);
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

// 4 continuous seeds (128-bit) for 1 job
// There're 16 jobs.
void sample_round_03(void)
{
	uint32_t seed, cntw;
	uint32_t *pseed, *pin;
	uint32_t v[4];
	int i;

	init_buf(in, 0x37, 1024);
	init_buf(out, 0x55, 1024);
	dump_buf(in, 64);
	pseed = (uint32_t *)out;
	pin = (uint32_t *)in;
	// 512 / 32 = 16
	cntw = dump_cntw();
	v[0] = *pseed;
	v[1] = *(pseed + 1);
	v[2] = *(pseed + 2);
	v[3] = *(pseed + 3);
	for (i = 0; i < cntw; i++) {
		v[0] = xxh32_round(v[0], *(const uint32_t *)pin++);
		v[1] = xxh32_round(v[1], *(const uint32_t *)pin++);
		v[2] = xxh32_round(v[2], *(const uint32_t *)pin++);
		v[3] = xxh32_round(v[3], *(const uint32_t *)pin++);
		*pseed = v[0];
		*(pseed + 1) = v[1];
		*(pseed + 2) = v[2];
		*(pseed + 3) = v[3];
		pseed += 4;
	}
	printf("output seed, i:0x%x\n", i);
	dump_buf(out, 64);
}

int main(void)
{
	t_round_03();
	sample_round_03();
	return 0;
}
