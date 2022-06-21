
	.arch armv8.2-a+sve

.macro init_index  idx:req
	mov	x4, 16
	index	\idx\().s, #0, w4
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

	.section .rodata.cts16,"aM",@progbits,16
	.align 16
XXH32_PRIME:
	.word	0x9E3779B1
	.word	0x85EBCA77
	.word	0xC2B2AE3D
	.word	0x27D4EB2F
	.word	0x165667B1
