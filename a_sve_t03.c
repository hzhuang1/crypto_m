#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define XXH_rotl64(x, r) ((x << r) | (x >> (64 - r)))

#define XXH64_DIGEST_NDWORDS	4

typedef struct {
	uint8_t*  buffer;       //!< pointer to data buffer for this job
	uint32_t  blk_len;          //!< length of buffer for this job in blocks.
	uint64_t digest[XXH64_DIGEST_NDWORDS] __attribute__((aligned(64)));
	uint64_t  result_digest;//!< final digest
	//JOB_STS   status;       //!< output job status
	//void*     user_data;    //!< pointer for user's job-related data
} XXH64_JOB;


/*-*************************************
 * Constants
 **************************************/
const uint64_t PRIME64_1 = 11400714785074694791ULL;
const uint64_t PRIME64_2 = 14029467366897019727ULL;
const uint64_t PRIME64_3 =  1609587929392839161ULL;
const uint64_t PRIME64_4 =  9650029242287828579ULL;
const uint64_t PRIME64_5 =  2870177450012600261ULL;


unsigned char in[1024], out[1024];

extern void rtl64_01(unsigned char *in, unsigned char *out);
extern void round64_01(unsigned char *acc, unsigned char *input);
extern void mround64_01(unsigned char *acc, unsigned char *val);

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

#if 0
XXH64_JOB *alloc_job(size_t size, int seed)
{
	XXH64_JOB *job;

	if (!size)
		return NULL;
	job = calloc(1, sizeof(XXH64_JOB));
	if (!job)
		return NULL;
	job->len = size;
	job->buffer = calloc(1, size);
	if (!job->buffer)
		goto out;
	job->digest[0] = seed + PRIME64_1 + PRIME64_2;
	job->digest[1] = seed + PRIME64_2;
	job->digest[2] = seed + 0;
	job->digest[3] = seed - PRIME64_1;
	init_buf(job->buffer, 0x37 + ((seed >> 8) & 0x3f), size);
	//set_buf(job->buffer, 0xa7, size);
	return job;
out:
	free(job);
	return NULL;
}

void free_job(XXH64_JOB *job)
{
	free(job->buffer);
	free(job);
}
#endif

static uint64_t xxh64_round(uint64_t acc, const uint64_t input)
{
	acc += input * PRIME64_2;
	acc = XXH_rotl64(acc, 31);
	acc *= PRIME64_1;
	return acc;
}

static uint64_t xxh64_merge_round(uint64_t acc, uint64_t val)
{
	val = xxh64_round(0, val);
	acc ^= val;
	acc = acc * PRIME64_1 + PRIME64_4;
	return acc;
}

void t_rtl_01(void)
{
	init_buf(in, 0x37, 256);
	init_buf(out, 0x55, 256);
	dump_buf(in, 64);
	printf("ASM version:\n");
	rtl64_01(in, out);
	dump_buf(out, 64);
	printf("C version:\n");
	{
		uint64_t tmp, *p, *q;
		int i;

		init_buf(out, 0x55, 256);
		p = (uint64_t *)in;
		q = (uint64_t *)out;
		for (i = 0; i < 64; i += 8, p++, q++) {
			tmp = XXH_rotl64(*p, 13);
			*q = tmp;
		}
	}
	dump_buf(out, 64);
}

void t_round_01(void)
{
	init_buf(in, 0x37, 256);
	init_buf(out, 0x55, 256);
	dump_buf(in, 64);
	// out works as seed
	printf("ASM version:\n");
	// out (ACC), in (INPUT)
	round64_01(out, in);
	dump_buf(out, 64);
	printf("C version:\n");
	{
		uint64_t tmp, *p, *q;
		int i;

		init_buf(out, 0x55, 256);
		p = (uint64_t *)in;
		q = (uint64_t *)out;
		for (i = 0; i < 64; i += 8, p++, q++) {
			tmp = xxh64_round(*q, *p);
			*q = tmp;
		}
	}
	dump_buf(out, 64);
}

void t_merge_round_01(void)
{
	init_buf(in, 0x37, 256);
	init_buf(out, 0x55, 256);
	dump_buf(in, 64);
	// out works as seed
	printf("ASM version:\n");
	// out (ACC), in (INPUT)
	mround64_01(out, in);
	dump_buf(out, 64);
	printf("C version:\n");
	{
		uint64_t tmp, *p, *q;
		int i;

		init_buf(out, 0x55, 256);
		p = (uint64_t *)in;
		q = (uint64_t *)out;
		for (i = 0; i < 64; i += 8, p++, q++) {
			tmp = xxh64_merge_round(*q, *p);
			*q = tmp;
		}
	}
	dump_buf(out, 64);
}

int main(void)
{
	//t_rtl_01();
	//t_round_01();
	t_merge_round_01();
	return 0;
}
