
	.arch armv8.2-a+sve

.macro xxh64_sve_save_stack
        stp     x29, x30, [sp, -48]!
        mov     x29, sp
.endm

.macro xxh64_sve_restore_stack
        mov     sp, x29
        ldp     x29, x30, [sp], #48
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

