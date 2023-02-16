
	.arch armv8.2-a+sve

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
