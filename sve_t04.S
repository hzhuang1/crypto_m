
	.arch armv8.2-a+sve2

/*
 * Zero extend on high 32-bit data in each 64-bit field.
 * void uxtw_01(unsigned char *in, unsigned char *out)
 */
	.global uxtw_01
	.type uxtw_01, %function
uxtw_01:
	ptrue	p0.b
	//ptrue	p0.b, VL64
	ld1b	z0.b, p0/z, [x0]
	uxtw	z1.d, p0/m, z0.d
	st1b	z1.b, p0, [x1]
	ret
	.size uxtw_01, .-uxtw_01


/*
 * Zero extend on high 32-bit data in each 64-bit field.
 * void uxtw_02(unsigned char *in, unsigned char *out)
 */
	.global uxtw_02
	.type uxtw_02, %function
uxtw_02:
	ptrue	p0.b
	ld1b	z0.b, p0/z, [x0]

	/* With 4 extra instructions, AND could replace UXTW. */
	ptrue	p1.d
	ptrue	p2.s
	eor	p1.b, p0/z, p1.b, p2.b
	mov	z1.d, #0

	and	z1.d, p1/m, z1.d, z0.d
	st1w	z1.s, p1, [x1]
	ret
	.size uxtw_02, .-uxtw_02

/*
 * Generate the sequence of [1,0,3,2,...].
 * void index_01(unsigned char *out);
 */
	.global index_01
	.type index_01, %function
index_01:
	ptrue	p7.d
	// set z7 to [ 1, 0, 3, 2, 5, 4, ... ] for tbl to swap adjacent lanes
	index   z7.d, #0, #1        // z7 = [ 0, 1, 2, 3, 4, 5... ]
	eor     z7.d, z7.d, #1      // z7 = [ 1, 0, 3, 2, 5, 4... ]
	st1d	{z7.d}, p7, [x0]
	ret
	.size index_01, .-index_01

/*
 * Exchange high 64-bit and low 64-bit for SVE128.
 * void ext_01(unsigned char *in, unsigned char *out);
 */
	.global ext_01
	.type ext_01, %function
ext_01:
	ldr	z0, [x0]
	ext	z0.b, z0.b, z0.b, 8
	str	z0, [x1]
	ret
	.size ext_01, .-ext_01

/*
 * De-interleave two vectors and format new two vectors.
 * void unzip_01(unsigned char *in, unsigned char *out);
 */
	.global unzip_01
	.type unzip_01, %function
unzip_01:
	ptrue	p7.d
	ld1d	z0.d, p7/z, [x0]
	ld1d	z1.d, p7/z, [x0, #1, MUL VL]
	uzp1	z2.s, z0.s, z1.s
	uzp2	z3.s, z0.s, z1.s
	st1d	{z2.d}, p7, [x1]
	st1d	{z3.d}, p7, [x1, #1, MUL VL]
	ret
	.size unzip_01, .-unzip_01


/*
 * Mix NEON & SVE2 instructions only on SVE-128.
 * void inner_mul_01(unsigned char *in, unsigned char *secret,
 *		unsigned char *out);
 */
	.global inner_mul_01
	.type inner_mul_01, %function
inner_mul_01:
	ptrue	p7.d
	ldr	q0, [x0]
	ldr	q6, [x0, #16]
	ldr	q12, [x0, #32]
	ldr	q13, [x0, #48]
	ldr	q1, [x1]
	ldr	q7, [x1, #16]
	ldr	q14, [x1, #32]
	ldr	q15, [x1, #48]
	ldr	q2, [x2]
	ldr	q8, [x2, #16]
	ldr	q16, [x2, #32]
	ldr	q17, [x2, #48]
	// v3, v9: swapped
	ext	v3.16b, v0.16b, v0.16b, #8 
	ext	v9.16b, v6.16b, v6.16b, #8
	ext	v18.16b, v12.16b, v12.16b, #8
	ext	v19.16b, v13.16b, v13.16b, #8
	// v4, v10: mixed_lo
	eor	v4.16b, v0.16b, v1.16b
	eor	v10.16b, v6.16b, v7.16b
	eor	v20.16b, v12.16b, v14.16b
	eor	v21.16b, v13.16b, v15.16b
	// v5, v11: mixed_hi
	rev64	v5.4s, v4.4s
	rev64	v11.4s, v10.4s
	rev64	v22.4s, v20.4s
	rev64	v23.4s, v21.4s
	// z3 = z4 * z5 + z3
	umlalb	z3.d, z4.s, z5.s
	umlalb	z9.d, z10.s, z11.s
	umlalb	z18.d, z20.s, z22.s
	umlalb	z19.d, z21.s, z23.s
	add	v2.2d, v2.2d, v3.2d
	add	v8.2d, v8.2d, v9.2d
	add	v16.2d, v16.2d, v18.2d
	add	v17.2d, v17.2d, v19.2d
	str	q2, [x2]
	str	q8, [x2, #16]
	str	q16, [x2, #32]
	str	q17, [x2, #48]
	//ld1d	z1.d, p7/z, [x1]
	//st1d	{z0.d}, p7, [x2]
	ret
	.size inner_mul_01, .-inner_mul_01
