#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define XXH32_DIGEST_NWORDS	4
#define XXH32_MAX_JOBS		16
#define XXH32_BLOCK_SIZE	64

typedef struct {
	uint8_t		*buffer;
	uint32_t	len;
	uint32_t	result_digest[XXH32_DIGEST_NWORDS] __attribute__((aligned(16)));
	// some fields are not contained
	//uint32_t	result_digest[XXH32_DIGEST_NWORDS];
} XXH32_JOB;

extern int dump_cntw(void);
extern void load_01(unsigned char *buf);
extern void load_02(unsigned char *in, unsigned char *out);
extern void load_stack_01(XXH32_JOB **jobs, int job_cnt, int block_cnt, void *buf);
extern void rev_01(unsigned char *in, unsigned char *out);
extern void rtl32_01(unsigned char *in, unsigned char *out);
extern void round32_01(unsigned char *in, unsigned char *out);
extern void round32_02(unsigned char *seed, unsigned char *in);
extern void round32_03(unsigned char *seed, unsigned char *in);
extern void round32_04(void *seed_buf, void *data_buf, int block_sz, int job_cnt);
extern void load_seed_01(void **jobs, int job_cnt, void *buffer);
extern void load_block_01(void **jobs, int job_cnt, void *buffer, int block_idx);

#define xxh_rotl32(x, r) ((x << r) | (x >> (32 - r)))

static const uint32_t PRIME32_1 = 2654435761U;
static const uint32_t PRIME32_2 = 2246822519U;
static const uint32_t PRIME32_3 = 3266489917U;
static const uint32_t PRIME32_4 =  668265263U;
static const uint32_t PRIME32_5 =  374761393U;

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

XXH32_JOB *alloc_job(size_t size, int seed)
{
	XXH32_JOB *job;

	if (!size)
		return NULL;
	job = calloc(1, sizeof(XXH32_JOB));
	if (!job)
		return NULL;
	job->len = size;
	job->buffer = calloc(1, size);
	if (!job->buffer)
		goto out;
	job->result_digest[0] = seed + PRIME32_1 + PRIME32_2;
	job->result_digest[1] = seed + PRIME32_2;
	job->result_digest[2] = seed + 0;
	job->result_digest[3] = seed - PRIME32_1;
	init_buf(job->buffer, 0x37 + ((seed >> 8) & 0x3f), size);
	return job;
out:
	free(job);
	return NULL;
}

void free_job(XXH32_JOB *job)
{
	free(job->buffer);
	free(job);
}

uint32_t xxh32_round(uint32_t seed, const uint32_t input)
{
	seed += input * PRIME32_2;
	seed = xxh_rotl32(seed, 13);
	seed *= PRIME32_1;
	return seed;
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

void t_load_stack_01(void)
{
	XXH32_JOB *job_vec[XXH32_MAX_JOBS];
	void *buf;
	int i, j, m, block_cnt = 2;
	size_t seed_size;
	uint32_t *pseed, *pin;
	uint32_t v[4], cntw;

	seed_size = XXH32_DIGEST_NWORDS * 4;
	for (i = 0; i < XXH32_MAX_JOBS; i++) {
		job_vec[i] = alloc_job(XXH32_BLOCK_SIZE, i * 10000);
		if (!job_vec[i])
			goto out;
	}
	buf = calloc(1, XXH32_MAX_JOBS * (seed_size + XXH32_BLOCK_SIZE));
	if (!buf)
		goto out_seed;
	load_stack_01(job_vec, XXH32_MAX_JOBS, 1, buf);
	dump_buf(buf, XXH32_MAX_JOBS * (seed_size + XXH32_BLOCK_SIZE));
	free(buf);
	for (i = 0; i < XXH32_MAX_JOBS; i++)
		free_job(job_vec[i]);
	return;
out_seed:
	i = XXH32_MAX_JOBS;
out:
	for (; i > 0; i--)
		free_job(job_vec[i - 1]);
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

void t_round_04(void)
{
	XXH32_JOB *job_vec[XXH32_MAX_JOBS];
	void *seed_buf, *data_buf;
	int i, j;
	size_t seed_size;
	uint32_t *pseed, *pin;
	uint32_t v[4], cntw;

	seed_size = XXH32_DIGEST_NWORDS * 4;
	for (i = 0; i < XXH32_MAX_JOBS; i++) {
		job_vec[i] = alloc_job(XXH32_BLOCK_SIZE * 2, i * 10000);
		if (!job_vec[i])
			goto out;
	}
	seed_buf = calloc(1, XXH32_MAX_JOBS * seed_size);
	if (!seed_buf)
		goto out_seed;
	data_buf = calloc(1, XXH32_MAX_JOBS * XXH32_BLOCK_SIZE);
	if (!data_buf)
		goto out_data;
	load_seed_01(job_vec, XXH32_MAX_JOBS, seed_buf);
	load_block_01(job_vec, XXH32_MAX_JOBS, data_buf, 0);
	round32_04(seed_buf, data_buf, XXH32_BLOCK_SIZE, XXH32_MAX_JOBS);
	dump_buf(seed_buf, XXH32_MAX_JOBS * seed_size);
	//dump_buf(data_buf, XXH32_MAX_JOBS * XXH32_BLOCK_SIZE);
	return;
out_data:
	free(seed_buf);
out_seed:
	i = XXH32_MAX_JOBS;
out:
	for (; i > 0; i--)
		free_job(job_vec[i - 1]);
}

void t_round_05(void)
{
	XXH32_JOB *job_vec[XXH32_MAX_JOBS];
	void *seed_buf, *data_buf;
	int i, j, m, block_cnt = 2;
	size_t seed_size;
	uint32_t *pseed, *pin;
	uint32_t v[4], cntw;

	seed_size = XXH32_DIGEST_NWORDS * 4;
	for (i = 0; i < XXH32_MAX_JOBS; i++) {
		job_vec[i] = alloc_job(XXH32_BLOCK_SIZE * 2, i * 10000);
		if (!job_vec[i])
			goto out;
	}
	seed_buf = calloc(1, XXH32_MAX_JOBS * seed_size);
	if (!seed_buf)
		goto out_seed;
	data_buf = calloc(1, XXH32_MAX_JOBS * XXH32_BLOCK_SIZE);
	if (!data_buf)
		goto out_data;
	load_seed_01(job_vec, XXH32_MAX_JOBS, seed_buf);
	for (m = 0; m < block_cnt; m++) {
		load_block_01(job_vec, XXH32_MAX_JOBS, data_buf, m);
		round32_04(seed_buf, data_buf, XXH32_BLOCK_SIZE, XXH32_MAX_JOBS);
	}
	dump_buf(seed_buf, XXH32_MAX_JOBS * seed_size);
	//dump_buf(data_buf, XXH32_MAX_JOBS * XXH32_BLOCK_SIZE);
	return;
out_data:
	free(seed_buf);
out_seed:
	i = XXH32_MAX_JOBS;
out:
	for (; i > 0; i--)
		free_job(job_vec[i - 1]);
}

void t_copy_digest_01(void)
{
	XXH32_JOB *job_vec[XXH32_MAX_JOBS];
	void *buffer;
	size_t seed_size;
	int i;

	seed_size = XXH32_DIGEST_NWORDS * 4;
	for (i = 0; i < XXH32_MAX_JOBS; i++) {
		job_vec[i] = alloc_job(XXH32_BLOCK_SIZE * 2, i * 10000);
		if (!job_vec[i])
			goto out;
	}
	buffer = calloc(1, XXH32_MAX_JOBS * seed_size);
	if (!buffer)
		goto out_buf;
	load_seed_01(job_vec, XXH32_MAX_JOBS, buffer);
	dump_buf(buffer, XXH32_MAX_JOBS * seed_size);
	return;
out_buf:
	i = XXH32_MAX_JOBS;
out:
	for (; i > 0; i--)
		free_job(job_vec[i - 1]);
}

void t_copy_buf_01(void)
{
	XXH32_JOB *job_vec[XXH32_MAX_JOBS];
	void *buffer;
	int i;

	for (i = 0; i < XXH32_MAX_JOBS; i++) {
		job_vec[i] = alloc_job(XXH32_BLOCK_SIZE * 2, i * 10000);
		if (!job_vec[i])
			goto out;
	}
	buffer = calloc(1, XXH32_MAX_JOBS * XXH32_BLOCK_SIZE);
	if (!buffer)
		goto out_buf;
	printf("first block\n");
	load_block_01(job_vec, XXH32_MAX_JOBS, buffer, 0);
	dump_buf(buffer, XXH32_MAX_JOBS * XXH32_BLOCK_SIZE);
	printf("next block\n");
	load_block_01(job_vec, XXH32_MAX_JOBS, buffer, 1);
	dump_buf(buffer, XXH32_MAX_JOBS * XXH32_BLOCK_SIZE);
	return;
out_buf:
	i = XXH32_MAX_JOBS;
out:
	for (; i > 0; i--)
		free_job(job_vec[i - 1]);
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
// sample_round_03() equals to t_round_03().
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

void sample_round_04(void)
{
	XXH32_JOB *job_vec[XXH32_MAX_JOBS];
	void *seed_buf, *data_buf;
	int i, j;
	size_t seed_size;
	uint32_t *pseed, *pin;
	uint32_t v[4], cntw;

	printf("%s:\n", __func__);
	seed_size = XXH32_DIGEST_NWORDS * 4;
	for (i = 0; i < XXH32_MAX_JOBS; i++) {
		job_vec[i] = alloc_job(XXH32_BLOCK_SIZE * 2, i * 10000);
		if (!job_vec[i])
			goto out;
	}
	seed_buf = calloc(1, XXH32_MAX_JOBS * seed_size);
	if (!seed_buf)
		goto out_seed;
	data_buf = calloc(1, XXH32_MAX_JOBS * XXH32_BLOCK_SIZE);
	if (!data_buf)
		goto out_data;
	cntw = dump_cntw();
	/* copy seeds into one seed_buf */
	for (i = 0; i < XXH32_MAX_JOBS; i++) {
		memcpy(seed_buf + (i * XXH32_DIGEST_NWORDS * 4),
			job_vec[i]->result_digest,
			seed_size);
	}
	/* copy data into one data_buf */
	for (i = 0; i < XXH32_MAX_JOBS; i++) {
		memcpy(data_buf + (i * XXH32_BLOCK_SIZE), job_vec[i]->buffer, XXH32_BLOCK_SIZE);
	}
	for (i = 0; i < XXH32_MAX_JOBS; i++) {
		v[0] = job_vec[i]->result_digest[0];
		v[1] = job_vec[i]->result_digest[1];
		v[2] = job_vec[i]->result_digest[2];
		v[3] = job_vec[i]->result_digest[3];
		pin = (uint32_t *)(data_buf + (i * XXH32_BLOCK_SIZE));
		for (j = 0; j < cntw; j++) {
			v[0] = xxh32_round(v[0], *(const uint32_t *)pin++);
			v[1] = xxh32_round(v[1], *(const uint32_t *)pin++);
			v[2] = xxh32_round(v[2], *(const uint32_t *)pin++);
			v[3] = xxh32_round(v[3], *(const uint32_t *)pin++);
		}
		pseed = (uint32_t *)(seed_buf + (i * XXH32_DIGEST_NWORDS * 4));
		*(pseed + 0) = v[0];
		*(pseed + 1) = v[1];
		*(pseed + 2) = v[2];
		*(pseed + 3) = v[3];
	}
	dump_buf(seed_buf, XXH32_MAX_JOBS * seed_size);
	return;
out_data:
	free(seed_buf);
out_seed:
	i = XXH32_MAX_JOBS;
out:
	for (; i > 0; i--)
		free_job(job_vec[i - 1]);
}

void sample_round_05(void)
{
	XXH32_JOB *job_vec[XXH32_MAX_JOBS];
	void *seed_buf, *data_buf;
	int i, j, block_cnt = 2, m;
	size_t seed_size;
	uint32_t *pseed, *pin;
	uint32_t v[4], cntw;

	printf("%s:\n", __func__);
	seed_size = XXH32_DIGEST_NWORDS * 4;
	for (i = 0; i < XXH32_MAX_JOBS; i++) {
		job_vec[i] = alloc_job(XXH32_BLOCK_SIZE * 2, i * 10000);
		if (!job_vec[i])
			goto out;
	}
	seed_buf = calloc(1, XXH32_MAX_JOBS * seed_size);
	if (!seed_buf)
		goto out_seed;
	data_buf = calloc(1, XXH32_MAX_JOBS * XXH32_BLOCK_SIZE);
	if (!data_buf)
		goto out_data;
	cntw = dump_cntw();
	/* copy seeds into one seed_buf */
	for (i = 0; i < XXH32_MAX_JOBS; i++) {
		memcpy(seed_buf + (i * XXH32_DIGEST_NWORDS * 4),
			job_vec[i]->result_digest,
			seed_size);
	}
	for (m = 0; m < block_cnt; m++) {
		/* copy data into one data_buf */
		for (i = 0; i < XXH32_MAX_JOBS; i++) {
			memcpy(data_buf + (i * XXH32_BLOCK_SIZE),
				job_vec[i]->buffer + m * XXH32_BLOCK_SIZE,
				XXH32_BLOCK_SIZE);
		}
		for (i = 0; i < XXH32_MAX_JOBS; i++) {
			v[0] = job_vec[i]->result_digest[0];
			v[1] = job_vec[i]->result_digest[1];
			v[2] = job_vec[i]->result_digest[2];
			v[3] = job_vec[i]->result_digest[3];
			pin = (uint32_t *)(data_buf + (i * XXH32_BLOCK_SIZE));
			for (j = 0; j < cntw; j++) {
				v[0] = xxh32_round(v[0], *(const uint32_t *)pin++);
				v[1] = xxh32_round(v[1], *(const uint32_t *)pin++);
				v[2] = xxh32_round(v[2], *(const uint32_t *)pin++);
				v[3] = xxh32_round(v[3], *(const uint32_t *)pin++);
			}
			pseed = (uint32_t *)(seed_buf + (i * XXH32_DIGEST_NWORDS * 4));
			*(pseed + 0) = v[0];
			*(pseed + 1) = v[1];
			*(pseed + 2) = v[2];
			*(pseed + 3) = v[3];
			job_vec[i]->result_digest[0] = v[0];
			job_vec[i]->result_digest[1] = v[1];
			job_vec[i]->result_digest[2] = v[2];
			job_vec[i]->result_digest[3] = v[3];
		}
	}
	dump_buf(seed_buf, XXH32_MAX_JOBS * seed_size);
	return;
out_data:
	free(seed_buf);
out_seed:
	i = XXH32_MAX_JOBS;
out:
	for (; i > 0; i--)
		free_job(job_vec[i - 1]);
}

void sample_copy_seed_from_jobs(void)
{
	XXH32_JOB *job_vec[XXH32_MAX_JOBS];
	void *buffer;
	int i;
	size_t seed_size;

	seed_size = XXH32_DIGEST_NWORDS * 4;
	for (i = 0; i < XXH32_MAX_JOBS; i++) {
		job_vec[i] = alloc_job(XXH32_BLOCK_SIZE * 2, i * 10000);
		if (!job_vec[i])
			goto out;
	}
	buffer = calloc(1, XXH32_MAX_JOBS * seed_size);
	if (!buffer)
		goto out_buf;
	for (i = 0; i < XXH32_MAX_JOBS; i++) {
		memcpy(buffer + (i * XXH32_DIGEST_NWORDS * 4),
			job_vec[i]->result_digest,
			seed_size);
	}
	dump_buf(buffer, XXH32_MAX_JOBS * seed_size);
	return;
out_buf:
	i = XXH32_MAX_JOBS;
out:
	for (; i > 0; i--)
		free_job(job_vec[i - 1]);
}

void sample_copy_data_from_jobs(void)
{
	XXH32_JOB *job_vec[XXH32_MAX_JOBS];
	void *buffer;
	int i;
	size_t seed_size;

	seed_size = XXH32_DIGEST_NWORDS * 4;
	for (i = 0; i < XXH32_MAX_JOBS; i++) {
		job_vec[i] = alloc_job(XXH32_BLOCK_SIZE * 2, i * 10000);
		if (!job_vec[i])
			goto out;
	}
	buffer = calloc(1, XXH32_MAX_JOBS * seed_size);
	if (!buffer)
		goto out_buf;
	for (i = 0; i < XXH32_MAX_JOBS; i++) {
		memcpy(buffer + (i * XXH32_BLOCK_SIZE), job_vec[i]->buffer, XXH32_BLOCK_SIZE);
	}
	printf("sample first block\n");
	dump_buf(buffer, XXH32_MAX_JOBS * XXH32_BLOCK_SIZE);
	for (i = 0; i < XXH32_MAX_JOBS; i++) {
		memcpy(buffer + (i * XXH32_BLOCK_SIZE),
			job_vec[i]->buffer + XXH32_BLOCK_SIZE,
			XXH32_BLOCK_SIZE);
	}
	printf("sample next block\n");
	dump_buf(buffer, XXH32_MAX_JOBS * XXH32_BLOCK_SIZE);
	return;
out_buf:
	i = XXH32_MAX_JOBS;
out:
	for (; i > 0; i--)
		free_job(job_vec[i - 1]);
}

int main(void)
{
	t_load_stack_01();
/*
	t_round_05();
	sample_round_05();
	t_copy_buf_01();
	sample_copy_data_from_jobs();
*/
	return 0;
}
