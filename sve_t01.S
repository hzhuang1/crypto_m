
	.arch armv8.2-a+sve

.macro init_index
	mov	x4, 4
	index	z0.s, #0, w4
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
	init_index
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
	init_index
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
