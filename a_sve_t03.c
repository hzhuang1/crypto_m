#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define XXH_rotl64(x, r) ((x << r) | (x >> (64 - r)))

#define XXH64_DIGEST_NDWORDS	4
#define XXH64_MAX_LANES		32
#define XXH64_BLOCK_SIZE	256

typedef struct {
	uint8_t*  buffer;       //!< pointer to data buffer for this job
	uint32_t  blk_len;          //!< length of buffer for this job in blocks.
	// Attribute caused digest field moving to ahead position.
	// So discard attribute.
	//uint64_t digest[XXH64_DIGEST_NDWORDS] __attribute__((aligned(32)));
	uint64_t digest[XXH64_DIGEST_NDWORDS];
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
extern void load_stack_01(XXH64_JOB **job_vecs, int job_cnt, int blk_cnt, void *buf);
extern void load_stack_02(XXH64_JOB **job_vecs, int job_cnt, int blk_cnt, void *buf);
extern void single_01(XXH64_JOB **job_vecs, int job_cnt, int blk_cnt, void *buf);

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

XXH64_JOB *alloc_job(size_t size, int seed)
{
	XXH64_JOB *job;

	if (!size)
		return NULL;
	job = calloc(1, sizeof(XXH64_JOB));
	if (!job)
		return NULL;
	job->blk_len = (size + XXH64_BLOCK_SIZE - 1) / XXH64_BLOCK_SIZE;
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

void t_load_stack_01(void)
{
	XXH64_JOB *job_vec[XXH64_MAX_LANES];
	void *buf;
	size_t seed_size;
	int i;

	seed_size = XXH64_DIGEST_NDWORDS * 8;
	for (i = 0; i < XXH64_MAX_LANES; i++) {
		job_vec[i] = alloc_job(XXH64_BLOCK_SIZE, i * 10000);
		if (!job_vec[i])
			goto out;
	}
	buf = calloc(1, XXH64_MAX_LANES * (seed_size + XXH64_BLOCK_SIZE));
	if (!buf)
		goto out_seed;
	{
		void *p = buf;
		for (int i = 0; i < 8; i++) {
			printf("job->buffer:0x%p, job->digest[0]:0x%p\n", job_vec[i]->buffer, &job_vec[i]->digest[0]);
			printf("digest[%d]:\n", i);
			memcpy(p, job_vec[i]->digest, seed_size);
			dump_buf(p, seed_size);
			p += seed_size;
		}
		printf("\n");
	}

	// SVE512 / 64bit = 8 (lanes)
	load_stack_01(job_vec, 8, 1, buf);
	//dump_buf(buf, XXH64_MAX_LANES * (seed_size + XXH64_BLOCK_SIZE));
	dump_buf(buf, 8 * (seed_size + XXH64_BLOCK_SIZE));
	free(buf);
	for (i = 0; i < XXH64_MAX_LANES; i++)
		free_job(job_vec[i]);
	return;
out_seed:
	i = XXH64_MAX_LANES;
out:
	for (; i > 0; i--)
		free_job(job_vec[i - 1]);
}

void t_load_stack_02(void)
{
	XXH64_JOB *job_vec[XXH64_MAX_LANES];
	void *buf;
	size_t seed_size;
	int i;

	seed_size = XXH64_DIGEST_NDWORDS * 8;
	for (i = 0; i < XXH64_MAX_LANES; i++) {
		job_vec[i] = alloc_job(XXH64_BLOCK_SIZE, i * 10000);
		if (!job_vec[i])
			goto out;
	}
	buf = calloc(1, XXH64_MAX_LANES * (seed_size + XXH64_BLOCK_SIZE));
	if (!buf)
		goto out_seed;

	// SVE512 / 64bit = 8 (lanes)
	load_stack_02(job_vec, 8, 1, buf);
	//dump_buf(buf, XXH64_MAX_LANES * (seed_size + XXH64_BLOCK_SIZE));
	dump_buf(buf, 8 * (seed_size + XXH64_BLOCK_SIZE));
	free(buf);
	for (i = 0; i < XXH64_MAX_LANES; i++)
		free_job(job_vec[i]);
	return;
out_seed:
	i = XXH64_MAX_LANES;
out:
	for (; i > 0; i--)
		free_job(job_vec[i - 1]);
}

void t_single_01(void)
{
	XXH64_JOB *job_vec[XXH64_MAX_LANES];
	void *buf;
	size_t seed_size;
	int i, seed;

	seed_size = XXH64_DIGEST_NDWORDS * 8;
	for (i = 0; i < XXH64_MAX_LANES; i++) {
		seed = i * 10000;
		job_vec[i] = alloc_job(XXH64_BLOCK_SIZE, seed);
		if (!job_vec[i])
			goto out;
	}
	buf = calloc(1, XXH64_MAX_LANES * (seed_size + XXH64_BLOCK_SIZE));
	if (!buf)
		goto out_seed;

	printf("ASM version:\n");
	// SVE512 / 64bit = 8 (lanes)
	single_01(job_vec, 4, 1, buf);
	//dump_buf(buf, XXH64_MAX_LANES * (seed_size + XXH64_BLOCK_SIZE));
	dump_buf(buf, 8 * (seed_size + XXH64_BLOCK_SIZE));
	printf("C version:\n");
	{
		for (i = 0; i < XXH64_MAX_LANES; i++) {
			uint64_t v1, v2, v3, v4;
			uint8_t *p = (uint8_t *)job_vec[i]->buffer;
			uint8_t *end = p + XXH64_BLOCK_SIZE;

			v1 = job_vec[i]->digest[0];
			v2 = job_vec[i]->digest[1];
			v3 = job_vec[i]->digest[2];
			v4 = job_vec[i]->digest[3];
			seed = i * 10000;
			init_buf(job_vec[i]->buffer,
				0x37 + ((seed >> 8) & 0x3f),
				XXH64_BLOCK_SIZE);
			do {
				v1 = xxh64_round(v1, *(uint64_t *)p);
				p += 8;
				v2 = xxh64_round(v2, *(uint64_t *)p);
				p += 8;
				v3 = xxh64_round(v3, *(uint64_t *)p);
				p += 8;
				v4 = xxh64_round(v4, *(uint64_t *)p);
				p += 8;
			} while (p < end);
			printf("lane %d: %lx-%lx-%lx-%lx\n",
				i, v1, v2, v3, v4);
		}
	}
	free(buf);
	for (i = 0; i < XXH64_MAX_LANES; i++)
		free_job(job_vec[i]);
	return;
out_seed:
	i = XXH64_MAX_LANES;
out:
	for (; i > 0; i--)
		free_job(job_vec[i - 1]);
}

int main(void)
{
	//t_rtl_01();
	//t_round_01();
	//t_merge_round_01();
	//t_load_stack_01();
	//t_load_stack_02();
	t_single_01();
	return 0;
}
