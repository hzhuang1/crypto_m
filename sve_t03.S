
	.arch armv8.2-a+sve

.macro xxh64_sve_save_stack
        stp     x29, x30, [sp, -48]!
        mov     x29, sp
.endm

.macro xxh64_sve_restore_stack
        mov     sp, x29
        ldp     x29, x30, [sp], #48
.endm

// Create both seed and data buf on stack
.macro xxh64_create_stack_buf_01  job_cnt:req, seed_buf:req, data_buf:req, tmp:req
	// Reserve the unified seed buffer for all data lanes.
	// Each lane costs 32-byte (64 * 4) long.
	mov	\tmp, \job_cnt, lsl #5
	sub	\seed_buf, sp, \tmp
	// Reserve the unified data buffer for all data lanes.
	// Each lane costs 256-byte long.
	mov	\tmp, \job_cnt, lsl #8
	sub	\data_buf, \seed_buf, \tmp
	mov	sp, \data_buf
.endm

.macro xxh64_free_stack_buf_01
	mov	sp, x29
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
	// tmp: jobs[1].digest, ranges from 0, ...
	// 16 is the offset of digest field
	add	\tmp, \tmp, #16
	// Read 256-bit seed value (64 * 4)
	ld1	{v7.16b}, [\tmp], 16
	ld1	{v8.16b}, [\tmp]
	// Save 256-bit seed value in the continous buffer
	st1	{v7.16b}, [\dst], 16
	st1	{v8.16b}, [\dst], 16
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
	add	\tmp, \tmp, \block_idx, lsl #8
/*
	ld1	{\t1\().4s, \t2\().4s, \t3\().4s, \t4\().4s}, [\tmp]
	st1	{\t1\().4s, \t2\().4s, \t3\().4s, \t4\().4s}, [\dst], 64
*/
	// Each data lane is 256-byte long.
	mov	x13, #256
110:
	ldr	x12, [\tmp], #8
	str	x12, [\dst], #8
	subs	x13, x13, #8
	bne	110b
	subs	\cnt, \cnt, #1
	bne	102b
.endm

/*
 * void rtl64_01(unsigned char *in, int bits);
 * Load data from param INOUT into Z0 register.
 * Output data from Z1 register into param INOUT.
 * Access: Z0, Z1, Z2
 */
.macro rotate_left_01	seed:req, tmp:req, bits
	// seed.d = (seed.d << bits) | (seed.d >> (64 - bits))
	lsl	\tmp\().d, \seed\().d, \bits
	lsr	\seed\().d, p0/m, \seed\().d, 64 - \bits
	orr	\seed\().d, p0/m, \seed\().d, \tmp\().d
.endm

	.global rtl64_01
	.type rtl64_01, %function
rtl64_01:
	ptrue	p0.b
	ld1b	z0.b, p0/z, [x0]
	rotate_left_01	z0, z1, 13
	st1b	z0.b, p0, [x1]
	ret
	.size rtl64_01, .-rtl64_01

/*
 * void round64_01(unsigned char *seed, unsigned char *in);
 */
.macro round_01		acc:req, input:req, tmp:req, prm1:req, prm2:req
	// acc += input * PRIME64_2;
	mla	\acc\().d, p0/m, \input\().d, \prm2\().d
	rotate_left_01	\acc, \tmp, 31
	// acc *= PRIME64_1
	mul	\acc\().d, p0/m, \acc\().d, \prm1\().d
.endm
	.global	round64_01
	.type round64_01, %function
round64_01:
	ptrue	p0.b
	// x0: for acc
	// x1: for input
	ld1b	z0.b, p0/z, [x0]
	ld1b	z1.b, p0/z, [x1]
	adr	x3, XXH64_PRIME
	// x2: PRIME64_01
	ldr	x2, [x3], 8
	mov	z3.d, p0/m, x2
	// x2: PRIME64_02
	ldr	x2, [x3]
	mov	z4.d, p0/m, x2
	round_01	z0, z1, z2, z3, z4
	st1b	z0.b, p0, [x0]
	ret
	.size round64_01, .-round64_01


.macro merge_round_01	acc:req, val:req, tmp1:req, tmp2:req, prm1:req, prm2:req, prm4:req
	// val = xxh64_round(0, val);
	mov	\tmp1\().d, 0
	round_01  \tmp1, \val, \tmp2, \prm1, \prm2
	// acc ^= val;
	eor	\acc\().d, p0/m, \acc\().d, \tmp1\().d
	// acc = acc * PRIME64_1 + PRIME64_4;
	mad	\acc\().d, p0/m, \prm1\().d, \prm4\().d
.endm
	.global mround64_01
	.type mround64_01, %function
mround64_01:
	ptrue	p0.b
	// x0: address of acc
	// Z0: acc
	// x1: address of val
	// Z1: val
	ld1b	z0.b, p0/z, [x0]
	ld1b	z1.b, p0/z, [x1]
	adr	x3, XXH64_PRIME
	// x2 & Z3: PRIME64_01
	ldr	x2, [x3], 8
	mov	z3.d, p0/m, x2
	// x2 & Z4: PRIME64_02
	ldr	x2, [x3], 16
	mov	z4.d, p0/m, x2
	// x2 & Z5: PRIME64_04
	ldr	x2, [x3]
	mov	z5.d, p0/m, x2
	merge_round_01  z0, z1, z2, z6, z3, z4, z5
	st1b	z0.b, p0, [x0]
	ret
	.size mround64_01, .-mround64_01


// void load_stack_01(XXH64_JOB **job_vec, int job_cnt, int blocks, void *buf)
	.global load_stack_01
	.type load_stack_01, %function
load_stack_01:
	xxh64_sve_save_stack
	// xxh64_create_stack_buf_01(int job_cnt, void *seed_buf, void *data_buf, void *tmp)
	xxh64_create_stack_buf_01  x1, x4, x5, x6
	// load_seed_from_jobs_01(jobs, job_cnt, buffer, src, dst, tmp, cnt);
	// src, dst, tmp, cnt are temporary registers
	load_seed_from_jobs_01  x0, x1, x4, x7, x8, x6, x10
	// load_block_from_jobs_01(jobs, job_cnt, buffer, block_idx, src, dst, tmp, cnt, t1, t2, t3, t4);
	mov	x11, #0
	load_block_from_jobs_01  x0, x1, x5, x11, x7, x8, x6, x10, v1, v2, v3, v4

	// copy data from stack to external buffer to test
	mov	x6, x1, lsl #8
	// x5: data_buf
	mov	x7, x5
	mov	x8, x3
10:
	ldr	x9, [x7], #8
	str	x9, [x8], #8
	subs	x6, x6, #8
	bne	10b
	// copy seeds from stack to external buffer to test
	mov	x6, x1, lsl #5
20:
	ldr	x9, [x7], #8
	str	x9, [x8], #8
	subs	x6, x6, #8
	bne	20b

	xxh64_free_stack_buf_01
	xxh64_sve_restore_stack
	ret
	.size load_stack_01, .-load_stack_01

// void xxh64_mb_sve(XXH64_JOB **job_vec, int job_cnt, int blocks)
        .global xxh64_mb_sve
        .type xxh64_mb_sve, %function
xxh64_mb_sve:
        xxh64_sve_save_stack

        xxh64_sve_restore_stack
        ret
        .size xxh64_mb_sve, .-xxh64_mb_sve


        .section .rodata.cst16,"aM",@progbits,16
        .align 16

XXH64_PRIME:
	.dword 0x9E3779B185EBCA87	// PRIME64_1
	.dword 0xC2B2AE3D27D4EB4F	// PRIME64_2
	.dword 0x165667B19E3779F9	// PRIME64_3
	.dword 0x85EBCA77C2B2AE63	// PRIME64_4
	.dword 0x27D4EB2F165667C5	// PRIME64_5

