
	.arch armv8.2-a+sve

.macro init_index  idx:req
	mov	x4, 16
	index	\idx\().s, #0, w4
.endm

// for seeds
.macro init_index_02 idx:req, tmp:req
	mov	\tmp, 16
	index	\idx\().s, #0, \tmp
.endm

// for IN data
.macro init_index_03 idx:req, tmp:req
	mov	\tmp, 64
	index	\idx\().s, #0, \tmp
.endm

// src, dst, tmp: all temporary registers
// Load seeds from different jobs, and save them in one continuous buffer.
.macro load_seed_from_jobs_01  jobs:req, job_cnt:req, buffer:req, src:req, dst:req, tmp:req, cnt:req
	// Avoid to use jobs and buffer directly. Since it may be used
	// in multiple times.
	mov	\src, \jobs
	mov	\dst, \buffer
	mov	\cnt, \job_cnt
101:
	// tmp: ranges from jobs[0], jobs[1], ...
	ldr	\tmp, [\src], #8
	// tmp: jobs[1].result_digest, ranges from 0, ...
	add	\tmp, \tmp, #16
	// Read 128-bit seed value
	ld1	{v7.16b}, [\tmp]
	// Save 128-bit seed value in the continous buffer
	st1	{v7.16b}, [\dst], #16
	subs	\cnt, \cnt, #1
	bne	101b
.endm

/*
 * IN: jobs, job_cnt, buffer, block_idx
 * OUT: src, dst, tmp, cnt, t1, t2, t3, t4
 */
.macro load_block_from_jobs_01  jobs:req, job_cnt:req, buffer:req, block_idx:req, src:req, dst:req, tmp:req, cnt:req, t1:req, t2:req, t3:req, t4:req
	// Avoid to use jobs and buffer directly. Since it may be used
	// in multiple times.
	mov	\src, \jobs
	mov	\dst, \buffer
	mov	\cnt, \job_cnt
102:
	// tmp: ranges from jobs[0], jobs[1], ...
	ldr	\tmp, [\src], #8
	// tmp: jobs[i].buffer, ranges from 0, ...
	ldr	\tmp, [\tmp]
	// tmp: block address in job[i].buffer (offset: 256-byte)
	//add	\tmp, \tmp, \block_idx, lsl #8
/*
	ld1	{\t1\().4s, \t2\().4s, \t3\().4s, \t4\().4s}, [\tmp]
	st1	{\t1\().4s, \t2\().4s, \t3\().4s, \t4\().4s}, [\dst], 64
*/
/*
	// 512-bit
	ld1w	z11.s, p0/z, [\tmp]
	st1w	z11.s, p0, [\dst]
	add	\tmp, \tmp, #16
	add	\dst, \dst, #16
	// 512-bit
	ld1w	z11.s, p0/z, [\tmp]
	st1w	z11.s, p0, [\dst]
	add	\tmp, \tmp, #16
	add	\dst, \dst, #16
	// 512-bit
	ld1w	z11.s, p0/z, [\tmp]
	//st1w	z11.s, p0, [\dst]
	add	\tmp, \tmp, #16
	add	\dst, \dst, #16
	// 512-bit
	ld1w	z11.s, p0/z, [\tmp]
	st1w	z11.s, p0, [\dst]
	add	\tmp, \tmp, #16
	add	\dst, \dst, #16
*/
	mov	x13, #256
	//mov	x13, #128
110:
	ldr	x12, [\tmp], #8
	str	x12, [\dst], #8
	subs	x13, x13, #8
	bne	110b
	subs	\cnt, \cnt, #1
	bne	102b
.endm

.macro save_seed_to_jobs_01  jobs:req, job_cnt, buffer:req, src:req, dst:req, tmp:req, cnt:req
	mov	\src, \buffer
	mov	\dst, \jobs
	mov	\cnt, \job_cnt
103:
	// tmp: ranges from jobs[0], jobs[1], ...
	ldr	\tmp, [\dst], #8
	// tmp: jobs[i].result_digest, ranges from 0, ...
	add	\tmp, \tmp, #16
	ld1	{v7.16b}, [\src], #16
	st1	{v7.16b}, [\tmp]
	subs	\cnt, \cnt, #1
	bne	103b
.endm

/*
 * int dump_cntw(void);
 */
	.global dump_cntw
	.type dump_cntw, %function
dump_cntw:
	// SVE-512: ret = 512 / 32 = 16
	// return 16 for SVE-512
	cntw	x0
	ret
	.size dump_cntw, .-dump_cntw

/*
 * void load_01(unsigned char *buf);
 */
	.global load_01
	.type load_01, %function
load_01:
	ptrue	p0.b, VL64
	init_index z0
	st1b	z0.b, p0, [x0]
	ret
	.size load_01, .-load_01

/*
 * void load_02(unsigned char *in, unsigned char *out);
 */
	.global load_02
	.type load_02, %function
load_02:
	ptrue	p0.b
	ptrue	p1.s
	init_index z0
	ld1w	z1.s, p0/z, [x0]
	// Index is stored in Z0 by macro init_index(). Step is 4.
	// Z0.s:
	// [0x0]: 00-00-00-00 04-00-00-00 08-00-00-00 0c-00-00-00
	// [0x10]: 10-00-00-00 14-00-00-00 18-00-00-00 1c-00-00-00
	// [0x20]: 20-00-00-00 24-00-00-00 28-00-00-00 2c-00-00-00
	// [0x30]: 30-00-00-00 34-00-00-00 38-00-00-00 3c-00-00-00
	// [0x40]: d5-d6-d7-d8 d9-da-db-dc e5-e6-e7-e8 e9-ea-eb-ec
	// [0x50]: f5-f6-f7-f8 f9-fa-fb-fc 05-06-07-08 09-0a-0b-0c
	// [0x60]: 15-16-17-18 19-1a-1b-1c 25-26-27-28 29-2a-2b-2c
	// [0x70]: 35-36-37-38 39-3a-3b-3c 45-46-47-48 49-4a-4b-4c
	// If UXTW 2, then:
	// Z1.s:
	// [x1 + Z0[31:0] * 4], [x1 + Z0[63:32] * 4], [x1 + Z0[95:64] * 4], [x1 + Z0[127:96] * 4],
	// [x1 + Z0[159:128] * 4], [x1 + Z0[191:160] * 4], [x1 + Z0[223:192] * 4], [x1 + Z0[255:224] * 4],
	// [x1 + Z0[287:256] * 4], [x1 + Z0[319:288] * 4], [x1 + Z0[351:320] * 4], [x1 + Z0[383:352] * 4],
	// [x1 + Z0[415:384] * 4], [x1 + Z0[447:416] * 4], [x1 + Z0[479:448] * 4], [x1 + Z0[511:480] * 4].
	// So all 32-bit
	ld1w	z1.s, p1/z, [x1, z0.s, UXTW 2]
	st1b	z1.b, p0, [x1]
	ret
	.size load_02, .-load_02

// Create both seed and data buf on stack
.macro xxh32_create_stack_buf_01  job_cnt:req, seed_buf:req, data_buf:req, tmp:req
	// Reserve the unified seed buffer for all data lanes.
	// Each lane costs 16-byte long.
	mov	\tmp, \job_cnt, lsl #4
	sub	\seed_buf, sp, \tmp
	// Reserve the unified data buffer for all data lanes.
	// Each lane costs 256-byte long.
	mov	\tmp, \job_cnt, lsl #8
	sub	\data_buf, \seed_buf, \tmp
	sub	\data_buf, \data_buf, \tmp
	mov	sp, \data_buf
.endm

.macro xxh32_free_stack_buf_01
	mov	sp, x29
.endm

.macro xxh32_load_stack_seed_01 v1:req, v2:req, v3:req, v4:req, seed_buf:req, offs:req
	ld1w	\v1\().s, p0/z, [\seed_buf, \offs\().s, UXTW 0]
	add	\seed_buf, \seed_buf, #4
	ld1w	\v2\().s, p0/z, [\seed_buf, \offs\().s, UXTW 0]
	add	\seed_buf, \seed_buf, #4
	ld1w	\v3\().s, p0/z, [\seed_buf, \offs\().s, UXTW 0]
	add	\seed_buf, \seed_buf, #4
	ld1w	\v4\().s, p0/z, [\seed_buf, \offs\().s, UXTW 0]
	add	\seed_buf, \seed_buf, #4
.endm

/*
 * void load_stack_01(void **jobs, int job_cnt, int block_cnt, void *buf);
 */
	.global load_stack_01
	.type load_stack_01, %function
load_stack_01:
	stp	x29, x30, [sp, #-48]!
	mov	x29, sp
	// xxh32_create_stack_buf_01(job_cnt, seed_buf, data_buf, tmp);
	xxh32_create_stack_buf_01  x1, x4, x5, x6
	// load_seed_from_jobs_01(jobs, job_cnt, buffer, src, dst, tmp, cnt);
	// src, dst, tmp, cnt are temporary registers
	load_seed_from_jobs_01  x0, x1, x4, x7, x8, x6, x10
	// load_block_from_jobs_01(jobs, job_cnt, buffer, block_idx, src, dst, tmp, cnt, t1, t2, t3, t4);
	mov	x11, #0
	load_block_from_jobs_01  x0, x1, x5, x11, x7, x8, x6, x10, v1, v2, v3, v4
	// copy data from stack to external buffer to test
	mov	x6, x1, lsl #6
	// x5: data_buf
	mov	x7, x5
	mov	x8, x3
10:
	ldr	x9, [x7], #4
	str	x9, [x8], #4
	subs	x6, x6, #4
	bne	10b
	// copy seeds from stack to external buffer to test
	mov	x6, x1, lsl #4
20:
	ldr	x9, [x7], #4
	str	x9, [x8], #4
	subs	x6, x6, #4
	bne	20b
	//init_index_02  z2, w6
	//xxh32_load_stack_seed_01  z3, z4, z5, z6, x4, z2

	xxh32_free_stack_buf_01
	ldp	x29, x30, [sp], #48
	ret
	.size load_stack_01, .-load_stack_01

/*
 * void load_stack_02(void **jobs, int job_cnt, int block_cnt, void *buf);
 */
	.global load_stack_02
	.type load_stack_02, %function
load_stack_02:
	stp	x29, x30, [sp, #-48]!
	mov	x29, sp
	// xxh32_create_stack_buf_01(job_cnt, seed_buf, data_buf, tmp);
	xxh32_create_stack_buf_01  x1, x4, x5, x6
	// load_seed_from_jobs_01(jobs, job_cnt, buffer, src, dst, tmp, cnt);
	// src, dst, tmp, cnt are temporary registers
	load_seed_from_jobs_01  x0, x1, x4, x7, x8, x6, x10
	// load_block_from_jobs_01(jobs, job_cnt, buffer, block_idx, src, dst, tmp, cnt, t1, t2, t3, t4);
	mov	x11, #0
10:
	load_block_from_jobs_01  x0, x1, x5, x11, x7, x8, x6, x10, v1, v2, v3, v4
	// copy data from stack to external buffer to test
	mov	x6, x1, lsl #6
	// x5: data_buf
	mov	x7, x5
	mov	x8, x3
20:
	ldr	x9, [x7], #4
	str	x9, [x8], #4
	subs	x6, x6, #4
	bne	20b
	// copy seeds from stack to external buffer to test
	mov	x6, x1, lsl #4
30:
	ldr	x9, [x7], #4
	str	x9, [x8], #4
	subs	x6, x6, #4
	bne	30b
	add	x11, x11, #1
	cmp	x11, x2
	bne	10b
	//init_index_02  z2, w6
	//xxh32_load_stack_seed_01  z3, z4, z5, z6, x4, z2

	xxh32_free_stack_buf_01
	ldp	x29, x30, [sp], #48
	ret
	.size load_stack_02, .-load_stack_02

/*
 * void load_stack_03(XXH32_JOB **jobs, int job_cnt, int block_cnt, void *buf);
 */
	.global load_stack_03
	.type load_stack_03, %function
load_stack_03:
	stp	x29, x30, [sp, #-48]!
	stp	x12, x13, [sp, #16]
	mov	x29, sp
	cbz	x2, 90f

	// x4 (updated): seed_buf in stack
	// x5 (updated): data_buf in stack
	// xxh32_create_stack_buf_01(job_cnt, seed_buf, data_buf, tmp);
	xxh32_create_stack_buf_01  x1, x4, x5, x6

	// w1 (RD-only): job_cnt
	whilelo	p0.s, wzr, w1
	// init_index_02(idx, tmp);
	init_index_02 z2, w6

	// x8: PRIME address
	adr	x8, XXH32_PRIME
	// x6/Z0: PRIME32_01
	ldr	x6, [x8], 4
	mov	z0.s, p0/m, w6
	// x6/Z1: PRIME32_02
	ldr	x6, [x8]
	mov	z1.s, p0/m, w6
	ptrue	p1.b

	// x11: block index
	mov	x11, #0
10:
	// load_block_from_jobs_01(jobs, job_cnt, buffer, block_idx, src, dst, tmp, cnt, t1, t2, t3, t4);
	//load_block_from_jobs_01  x0, x1, x5, x11, x7, x8, x6, x10, v1, v2, v3, v4
	load_block_from_jobs_01  x0, x1, x5, x11, x7, x8, x6, x10, v11, v12, v13, v14

	mov	x8, x5
	// x10: block size
	//mov	x10, #64	// 64-word = 64 * 32-bit = 2048-bit
	mov	x10, #16
	// debug start
	mov	x9, #0x20
	mov	z11.s, p0/m, w9
	mov	x9, x3
	// debug end
/*
	// dump data in stack
15:
	//mov	x10, #16
17:
	mov	x6, #256
19:
	ldr	x7, [x8], #8
	str	x7, [x9], #8
	subs	x6, x6, #8
	bne	19b
	//subs	x10, x10, #1
	//bne	17b
	subs	x1, x1, #1
	bne	15b
	b	90f
	// dump data in stack end
*/
20:
	// load data from stack
	ld1w	z7.s, p0/z, [x8, z2.s, UXTW 2]
	add	x8, x8, #4
	ld1w	z8.s, p0/z, [x8, z2.s, UXTW 2]
	add	x8, x8, #4
	ld1w	z9.s, p0/z, [x8, z2.s, UXTW 2]
	add	x8, x8, #4
	ld1w	z10.s, p0/z, [x8, z2.s, UXTW 2]
	add	x8, x8, #4

	st1b	z7.b, p1, [x9]
	//subs	x10, x10, #4
	subs	x10, x10, #1
	add	x9, x9, #64
	st1b	z8.b, p1, [x9]
	add	x9, x9, #64
	st1b	z9.b, p1, [x9]
	add	x9, x9, #64
	st1b	z10.b, p1, [x9]
	add	x9, x9, #64
	bne	20b
90:
	xxh32_free_stack_buf_01
	ldp	x12, x13, [sp, #16]
	ldp	x29, x30, [sp], #48
	ret
	.size load_stack_03, .-load_stack_03

/*
 * void rev_01(unsigned char *in, unsigned char *out);
 */
	.global rev_01
	.type rev_01, %function
rev_01:
	ptrue	p0.b
	ld1b	z0.b, p0/z, [x0]
	revh	z1.s, p0/m, z0.s
	st1b	z1.b, p0, [x1]
	ret
	.size rev_01, .-rev_01

/*
 * void rtl32_01(unsigned char *in, int bits);
 * Load data from param INOUT into Z0 register.
 * Output data from Z1 register into param INOUT.
 * Access: Z0, Z1, Z2
 */
.macro rotate_left_01	seed:req, tmp:req, bits
	lsl	\tmp\().s, \seed\().s, \bits
	lsr	\seed\().s, p0/m, \seed\().s, 32 - \bits
	orr	\seed\().s, p0/m, \seed\().s, \tmp\().s
.endm

	.global rtl32_01
	.type rtl32_01, %function
rtl32_01:
	ptrue	p0.b
	ld1b	z0.b, p0/z, [x0]
	rotate_left_01	z0, z1, 13
	st1b	z0.b, p0, [x1]
	ret
	.size rtl2_01, .-rtl32_01

/*
 * void round32_01(unsigned char *seed, unsigned char *in);
 */
.macro round_01		seed:req, in:req, tmp:req, prm1:req, prm2:req
	// seed += in * PRIM32_2;
	mla	\seed\().s, p0/m, \in\().s, \prm2\().s
	rotate_left_01	\seed, \tmp, 13
	mul	\seed\().s, p0/m, \seed\().s, \prm1\().s
.endm
	.global	round32_01
	.type round32_01, %function
round32_01:
	ptrue	p0.b
	// x0: for seed
	// x1: for IN
	ld1b	z0.b, p0/z, [x0]
	ld1b	z1.b, p0/z, [x1]
	adr	x3, XXH32_PRIME
	// x2: PRIME32_01
	ldr	x2, [x3], 4
	mov	z3.s, p0/m, w2
	// x2: PRIME32_02
	ldr	x2, [x3]
	mov	z4.s, p0/m, w2
	round_01	z0, z1, z2, z3, z4
	st1b	z0.b, p0, [x0]
	ret
	.size round32_01, .-round32_01

/*
 * void round32_02(unsigned char *seed, unsigned char *in);
 */
// round32_01: only one seed
// round32_02: there're 16 seeds
	.global round32_02
	.type round32_02, %function
round32_02:
	ptrue	p0.b
	// x0: for seed
	// x1: for IN
	// z2: index
	init_index  z2
	// x5: cntw
	cntw	x5
.loop:
	cbz	x5, .return
	// load seed
	ld1w	z0.s, p0/z, [x0, z2.s, UXTW 2]
	// load IN
	ld1w	z1.s, p0/z, [x1, z2.s, UXTW 2]
	adr	x3, XXH32_PRIME
	// x2: PRIME32_01
	ldr	x2, [x3], 4
	// load PRIME32_01
	mov	z3.s, p0/m, w2
	// x2: PRIME32_02
	ldr	x2, [x3]
	// load PRIME32_02
	mov	z4.s, p0/m, w2
	// test
	round_01	z0, z1, z5, z3, z4
	st1w	z0.s, p0, [x0, z2.s, UXTW 2]
	add	x0, x0, #4
	add	x1, x1, #4
	//st1w	z2.s, p0, [x0]	// test dump z2
	sub	x5, x5, #1
	b	.loop
.return:
	ret
	.size round32_02, .-round32_02

/*
 * void round32_03(unsigned char *seed, unsigned char *in)
 */
// round32_01: only one seed
// round32_02: there're 16 seeds. One seed for 512-bit.
// round32_03: there're 4 seeds for one job. Each seed is 32-bit. And there're 4 jobs.
.macro rotate_left_x4_01  v1:req, v2:req, v3:req, v4:req, t1:req, t2:req, t3:req, t4:req, bits:req
	lsl	\t1\().s, \v1\().s, \bits
	lsl	\t2\().s, \v2\().s, \bits
	lsl	\t3\().s, \v3\().s, \bits
	lsl	\t4\().s, \v4\().s, \bits
	lsr	\v1\().s, p0/m, \v1\().s, 32 - \bits
	lsr	\v2\().s, p0/m, \v2\().s, 32 - \bits
	lsr	\v3\().s, p0/m, \v3\().s, 32 - \bits
	lsr	\v4\().s, p0/m, \v4\().s, 32 - \bits
	orr	\v1\().s, p0/m, \v1\().s, \t1\().s
	orr	\v2\().s, p0/m, \v2\().s, \t2\().s
	orr	\v3\().s, p0/m, \v3\().s, \t3\().s
	orr	\v4\().s, p0/m, \v4\().s, \t4\().s
.endm

.macro round_x4_01  v1:req, v2:req, v3:req, v4:req, in1:req, in2:req, in3:req, in4:req, prm1:req, prm2:req
	// seed += in * PRIME32_2
	mla	\v1\().s, p0/m, \in1\().s, \prm2\().s
	mla	\v2\().s, p0/m, \in2\().s, \prm2\().s
	mla	\v3\().s, p0/m, \in3\().s, \prm2\().s
	mla	\v4\().s, p0/m, \in4\().s, \prm2\().s
	// IN registers are useless, use them as tmp registers now.
	rotate_left_x4_01  \v1, \v2, \v3, \v4, \in1, \in2, \in3, \in4, 13
	mul	\v1\().s, p0/m, \v1\().s, \prm1\().s
	mul	\v2\().s, p0/m, \v2\().s, \prm1\().s
	mul	\v3\().s, p0/m, \v3\().s, \prm1\().s
	mul	\v4\().s, p0/m, \v4\().s, \prm1\().s
.endm
	.global  round32_03
	.type round32_03, %function
round32_03:
	ptrue	p0.b
	// x0: seed buffer (all seeds in one buffer)
	// x1: IN buffer
	// z2: index for seed
	init_index  z2
	// x5: cntw
	cntw	x5
	//mov	x5, #8
	// x4: temporary pointer of seed buffer
	mov	x4, x0
	// There could be 16 jobs one Z register
	// load seed v1
	ld1w	z3.s, p0/z, [x4, z2.s, UXTW 0]
	add	x4, x4, #4
	// load seed v2
	ld1w	z4.s, p0/z, [x4, z2.s, UXTW 0]
	add	x4, x4, #4
	// load seed v3
	ld1w	z5.s, p0/z, [x4, z2.s, UXTW 0]
	add	x4, x4, #4
	// load seed v4
	ld1w	z6.s, p0/z, [x4, z2.s, UXTW 0]
	add	x4, x4, #4
.loop03:
	cbz	x5, .return03
	// load IN for v1
	ld1w	z7.s, p0/z, [x1, z2.s, UXTW 2]
	add	x1, x1, #4
	// load IN for v2
	ld1w	z8.s, p0/z, [x1, z2.s, UXTW 2]
	add	x1, x1, #4
	// load IN for v3
	ld1w	z9.s, p0/z, [x1, z2.s, UXTW 2]
	add	x1, x1, #4
	// load IN
	ld1w	z10.s, p0/z, [x1, z2.s, UXTW 2]
	add	x1, x1, #4
	// x3: PRIME address
	adr	x3, XXH32_PRIME
	// x2: temporary register for PRIME32_01
	ldr	x2, [x3], 4
	// Z0: PRIME32_01
	mov	z0.s, p0/m, w2
	// x2: temporary register for PRIME32_02
	ldr	x2, [x3]
	// Z1: PRIME32_02
	mov	z1.s, p0/m, w2
	round_x4_01  z3, z4, z5, z6, z7, z8, z9, z10, z0, z1
	st1w	z3.s, p0, [x0, z2.s, UXTW 0]
	add	x0, x0, #4
	st1w	z4.s, p0, [x0, z2.s, UXTW 0]
	add	x0, x0, #4
	st1w	z5.s, p0, [x0, z2.s, UXTW 0]
	add	x0, x0, #4
	st1w	z6.s, p0, [x0, z2.s, UXTW 0]
	add	x0, x0, #4
	sub	x5, x5, #4
	b	.loop03
.return03:
	ret
	.size round32_03, .-round32_03

/*
 * void round32_04(void *seed_buf, void *data_buf, int block_sz, int job_cnt);
 */
	.global round32_04
	.type round32_04, %function
round32_04:
	// x5: block_sz
	mov	x5, x2
	// w3: job_cnt
	whilelo	p0.s, wzr, w3
	// x0: seed buffer (all seeds in one buffer)
	// x1: IN buffer
	// z2: index for seed
	init_index  z2
	init_index_03 z12, w6
	// x4: temporary pointer of seed buffer
	mov	x4, x0
	// There could be 16 jobs one Z register
	// load seed v1
	ld1w	z3.s, p0/z, [x4, z2.s, UXTW 0]
	add	x4, x4, #4
	// load seed v2
	ld1w	z4.s, p0/z, [x4, z2.s, UXTW 0]
	add	x4, x4, #4
	// load seed v3
	ld1w	z5.s, p0/z, [x4, z2.s, UXTW 0]
	add	x4, x4, #4
	// load seed v4
	ld1w	z6.s, p0/z, [x4, z2.s, UXTW 0]
	add	x4, x4, #4
.loop04:
	cbz	x5, .return04
	// load IN for v1
	ld1w	z7.s, p0/z, [x1, z12.s, UXTW 2]
	mov	z11.d, z7.d
	add	x1, x1, #4
	// load IN for v2
	ld1w	z8.s, p0/z, [x1, z12.s, UXTW 2]
	add	x1, x1, #4
	// load IN for v3
	ld1w	z9.s, p0/z, [x1, z12.s, UXTW 2]
	add	x1, x1, #4
	// load IN
	ld1w	z10.s, p0/z, [x1, z12.s, UXTW 2]
	add	x1, x1, #4
	// x3: PRIME address
	adr	x3, XXH32_PRIME
	// x2: temporary register for PRIME32_01
	ldr	x2, [x3], 4
	// Z0: PRIME32_01
	mov	z0.s, p0/m, w2
	// x2: temporary register for PRIME32_02
	ldr	x2, [x3]
	// Z1: PRIME32_02
	mov	z1.s, p0/m, w2
	round_x4_01  z3, z4, z5, z6, z7, z8, z9, z10, z0, z1
	sub	x5, x5, #16
	b	.loop04
.return04:
	st1w	z3.s, p0, [x0, z2.s, UXTW 0]
	add	x0, x0, #4
	st1w	z4.s, p0, [x0, z2.s, UXTW 0]
	add	x0, x0, #4
	st1w	z5.s, p0, [x0, z2.s, UXTW 0]
	add	x0, x0, #4
	st1w	z6.s, p0, [x0, z2.s, UXTW 0]
	add	x0, x0, #4
/*
	ptrue	p1.b
	st1b	z3.b, p1, [x0]
	add	x0, x0, #64
	//st1b	z11.b, p1, [x0]
	st1b	z4.b, p1, [x0]
	add	x0, x0, #64
	st1b	z5.b, p1, [x0]
	add	x0, x0, #64
	st1b	z6.b, p1, [x0]
	add	x0, x0, #64
*/
	ret
	.size round32_04, .-round32_04

/*
 * void stack_round_01(void **jobs, int job_cnt, int block_cnt, void *buf);
 */
	.global stack_round_01
	.type stack_round_01, %function
stack_round_01:
	stp	x29, x30, [sp, #-48]!
	mov	x29, sp
	cbz	x2, 90f

	// x4 (updated): seed_buf in stack
	// x5 (updated): data_buf in stack
	// xxh32_create_stack_buf_01(job_cnt, seed_buf, data_buf, tmp);
	xxh32_create_stack_buf_01  x1, x4, x5, x6

	// w1 (RD-only): job_cnt
	whilelo	p0.s, wzr, w1
	// init_index_02(idx, tmp);
	init_index_02 z2, w6
	init_index_03 z12, w6

	// x8: PRIME address
	adr	x8, XXH32_PRIME
	// x6/Z0: PRIME32_01
	ldr	x6, [x8], 4
	mov	z0.s, p0/m, w6
	// x6/Z1: PRIME32_02
	ldr	x6, [x8]
	mov	z1.s, p0/m, w6
	ptrue	p1.b
	mov	x9, x3

	// load_seed_from_jobs_01(jobs, job_cnt, buffer, src, dst, tmp, cnt);
	// x4 (RD-only): seed_buf in stack
	load_seed_from_jobs_01  x0, x1, x4, x7, x8, x6, x10

	// load seed from stack
	// x7: seed_buf
	mov	x7, x4
	ld1w	z3.s, p0/z, [x7, z2.s, UXTW 0]
	add	x7, x7, #4
	ld1w	z4.s, p0/z, [x7, z2.s, UXTW 0]
	add	x7, x7, #4
	ld1w	z5.s, p0/z, [x7, z2.s, UXTW 0]
	add	x7, x7, #4
	ld1w	z6.s, p0/z, [x7, z2.s, UXTW 0]

	// x11: block index
	mov	x11, #0
10:
	// load_block_from_jobs_01(jobs, job_cnt, buffer, block_idx, src, dst, tmp, cnt, t1, t2, t3, t4);
	//load_block_from_jobs_01  x0, x1, x5, x11, x7, x8, x6, x10, v1, v2, v3, v4
	load_block_from_jobs_01  x0, x1, x5, x11, x7, x8, x6, x10, v7, v8, v9, v10

	mov	x8, x5
	// x10: block size
	mov	x10, #16	// 2048 bit / 128 bit-per-row = 16 row
20:
	// load data from stack
	ld1w	z7.s, p0/z, [x8, z12.s, UXTW 2]
	add	x8, x8, #4
	ld1w	z8.s, p0/z, [x8, z12.s, UXTW 2]
	add	x8, x8, #4
	ld1w	z9.s, p0/z, [x8, z12.s, UXTW 2]
	add	x8, x8, #4
	ld1w	z10.s, p0/z, [x8, z12.s, UXTW 2]
	add	x8, x8, #4

	round_x4_01  z3, z4, z5, z6, z7, z8, z9, z10, z0, z1
	subs	x10, x10, #1
	str	x8, [x3], #8
	bne	20b
/*
	st1w	z3.s, p0, [x3]
	add	x3, x3, #4
	st1w	z4.s, p0, [x3]
	add	x3, x3, #4
	st1w	z5.s, p0, [x3]
	add	x3, x3, #4
	st1w	z6.s, p0, [x3]
	add	x3, x3, #4
	st1w	z3.s, p0, [x3, z2.s, UXTW 0]
	add	x3, x3, #4
	st1w	z4.s, p0, [x3, z2.s, UXTW 0]
	add	x3, x3, #4
	st1w	z5.s, p0, [x3, z2.s, UXTW 0]
	add	x3, x3, #4
	st1w	z6.s, p0, [x3, z2.s, UXTW 0]
	add	x3, x3, #4
	b	90f
*/
/*
	add	x11, x11, #1
	cmp	x11, x2
	bne	10b
*/

	// save seeds into seed_buf
	mov	x8, x4
	st1w	z3.s, p0, [x8, z2.s, UXTW 0]
	add	x8, x8, #4
	st1w	z4.s, p0, [x8, z2.s, UXTW 0]
	add	x8, x8, #4
	st1w	z5.s, p0, [x8, z2.s, UXTW 0]
	add	x8, x8, #4
	st1w	z6.s, p0, [x8, z2.s, UXTW 0]
	// save seeds into jobs
	save_seed_to_jobs_01  x0, x1, x4, x7, x8, x6, x10
90:
/*
	//st1b	z2.b, p1, [x3]
	mov	x7, x5
	mov	x8, x3
	mov	x6, x1, lsl #6
91:
	ldr	x10, [x7], #4
	str	x10, [x8], #4
	subs	x6, x6, #4
	bne	91b
	mov	x6, x1, lsl #4
92:
	ldr	x10, [x7], #4
	str	x10, [x8], #4
	subs	x6, x6, #4
	bne	92b
*/

	xxh32_free_stack_buf_01
	ldp	x29, x30, [sp], #48
	ret
	.size stack_round_01, .-stack_round_01

/*
 * void load_seed_01(void **jobs, int job_cnt, void *buffer);
 */
	.global load_seed_01
	.type load_seed_01, %function
load_seed_01:
	load_seed_from_jobs_01  x0, x1, x2, x4, x5, x6, x7
	ret
	.size load_seed_01, .-load_seed_01

/*
 * void load_block_01(void *jobs, int job_cnt, void *buffer, int block_idx);
 */
/*
	jobs		.equ	x0
	job_cnt		.equ	w1
	buffer		.equ	x2
	src		.equ	x5
	dst		.equ	x6
	tmp		.equ	x8
	tmpw		.equ	w8
*/
	.global load_block_01
	.type load_block_01, %function
load_block_01:
	load_block_from_jobs_01  x0, x1, x2, x3, x4, x5, x6, x7, v0, v1, v2, v3
	ret
	.size load_block_01, .-load_block_01

	.section .rodata.cts16,"aM",@progbits,16
	.align 16
XXH32_PRIME:
	.word	0x9E3779B1
	.word	0x85EBCA77
	.word	0xC2B2AE3D
	.word	0x27D4EB2F
	.word	0x165667B1
