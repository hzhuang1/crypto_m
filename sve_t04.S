
	.arch armv8.2-a+sve

/*
 * Zero extend on high 32-bit data in each 64-bit field.
 * void void uxtw_01(unsigned char *in, unsigned char *out)
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
 * void void uxtw_02(unsigned char *in, unsigned char *out)
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
