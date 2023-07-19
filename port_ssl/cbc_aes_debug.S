
	.arch armv8-a+crypto

.text
.align  5
.Lrcon:
.long   0x01,0x01,0x01,0x01
.long   0x0c0f0e0d,0x0c0f0e0d,0x0c0f0e0d,0x0c0f0e0d     // rotate-n-splat
.long   0x1b,0x1b,0x1b,0x1b


/*
 * void aes_v8_set_encrypt_key(const unsigned char *userKey,
				unsigned int bits, AES_KEY *key);
 */
.globl  aes_v8_set_encrypt_key
.type   aes_v8_set_encrypt_key,%function
.align  5
aes_v8_set_encrypt_key:
.Lenc_key:
        stp     x29,x30,[sp,#-16]!
        add     x29,sp,#0
        mov     x3,#-1
        cmp     x0,#0
        b.eq    .Lenc_key_abort
        cmp     x2,#0
        b.eq    .Lenc_key_abort
        mov     x3,#-2
        cmp     w1,#128
        b.lt    .Lenc_key_abort
        cmp     w1,#256
        b.gt    .Lenc_key_abort
        tst     w1,#0x3f
        b.ne    .Lenc_key_abort

        adr     x3,.Lrcon
        cmp     w1,#192

	# clear V0
        eor     v0.16b,v0.16b,v0.16b
	# load user key (first 128-bit) into V3
        ld1     {v3.16b},[x0],#16
        mov     w1,#8           // reuse w1
	# load rcon into V1 & V2
        ld1     {v1.4s,v2.4s},[x3],#32

        b.lt    .Loop128
        b.eq    .L192
        b       .L256

.align  4
.Loop128:
	# debug
	#st1	{v2.16b}, [x2], #16
	#st1	{v3.16b}, [x2], #16
	#st1	{v2.16b}, [x2], #16
	#tbl	v6.16b, {v3.16b}, v2.16b
	#st1	{v6.16b}, [x2], #16
	#st1	{v2.16b}, [x2], #16
	#ext	v5.16b, v0.16b, v3.16b, #12
	#st1	{v5.16b}, [x2], #16
	#st1	{v2.16b}, [x2], #16
	#b	.Ldone
	# debug end
        tbl     v6.16b,{v3.16b},v2.16b
        ext     v5.16b,v0.16b,v3.16b,#12
        st1     {v3.4s},[x2],#16
        aese    v6.16b,v0.16b
        subs    w1,w1,#1

        eor     v3.16b,v3.16b,v5.16b
        ext     v5.16b,v0.16b,v5.16b,#12
        eor     v3.16b,v3.16b,v5.16b
        ext     v5.16b,v0.16b,v5.16b,#12
        eor     v6.16b,v6.16b,v1.16b
        eor     v3.16b,v3.16b,v5.16b
        shl     v1.16b,v1.16b,#1
        eor     v3.16b,v3.16b,v6.16b
        b.ne    .Loop128

        ld1     {v1.4s},[x3]

        tbl     v6.16b,{v3.16b},v2.16b
        ext     v5.16b,v0.16b,v3.16b,#12
        st1     {v3.4s},[x2],#16
        aese    v6.16b,v0.16b

        eor     v3.16b,v3.16b,v5.16b
        ext     v5.16b,v0.16b,v5.16b,#12
        eor     v3.16b,v3.16b,v5.16b
        ext     v5.16b,v0.16b,v5.16b,#12
        eor     v6.16b,v6.16b,v1.16b
        eor     v3.16b,v3.16b,v5.16b
        shl     v1.16b,v1.16b,#1
        eor     v3.16b,v3.16b,v6.16b

        tbl     v6.16b,{v3.16b},v2.16b
        ext     v5.16b,v0.16b,v3.16b,#12
        st1     {v3.4s},[x2],#16
        aese    v6.16b,v0.16b

        eor     v3.16b,v3.16b,v5.16b
        ext     v5.16b,v0.16b,v5.16b,#12
        eor     v3.16b,v3.16b,v5.16b
        ext     v5.16b,v0.16b,v5.16b,#12
        eor     v6.16b,v6.16b,v1.16b
        eor     v3.16b,v3.16b,v5.16b
        eor     v3.16b,v3.16b,v6.16b
        st1     {v3.4s},[x2]
        add     x2,x2,#0x50

        mov     w12,#10
        b       .Ldone

.align  4
.L192:
        ld1     {v4.8b},[x0],#8
        movi    v6.16b,#8                       // borrow v6.16b
        st1     {v3.4s},[x2],#16
        sub     v2.16b,v2.16b,v6.16b    // adjust the mask

.Loop192:
        tbl     v6.16b,{v4.16b},v2.16b
        ext     v5.16b,v0.16b,v3.16b,#12
        st1     {v4.8b},[x2],#8
        aese    v6.16b,v0.16b
        subs    w1,w1,#1

        eor     v3.16b,v3.16b,v5.16b
        ext     v5.16b,v0.16b,v5.16b,#12
        eor     v3.16b,v3.16b,v5.16b
        ext     v5.16b,v0.16b,v5.16b,#12
        eor     v3.16b,v3.16b,v5.16b

        dup     v5.4s,v3.s[3]
        eor     v5.16b,v5.16b,v4.16b
        eor     v6.16b,v6.16b,v1.16b
        ext     v4.16b,v0.16b,v4.16b,#12
        shl     v1.16b,v1.16b,#1
        eor     v4.16b,v4.16b,v5.16b
        eor     v3.16b,v3.16b,v6.16b
        eor     v4.16b,v4.16b,v6.16b
        st1     {v3.4s},[x2],#16
        b.ne    .Loop192

        mov     w12,#12
        add     x2,x2,#0x20
        b       .Ldone

.align  4
.L256:
        ld1     {v4.16b},[x0]
        mov     w1,#7
        mov     w12,#14
        st1     {v3.4s},[x2],#16

.Loop256:
        tbl     v6.16b,{v4.16b},v2.16b
        ext     v5.16b,v0.16b,v3.16b,#12
        st1     {v4.4s},[x2],#16
        aese    v6.16b,v0.16b
        subs    w1,w1,#1

        eor     v3.16b,v3.16b,v5.16b
        ext     v5.16b,v0.16b,v5.16b,#12
        eor     v3.16b,v3.16b,v5.16b
        ext     v5.16b,v0.16b,v5.16b,#12
        eor     v6.16b,v6.16b,v1.16b
        eor     v3.16b,v3.16b,v5.16b
        shl     v1.16b,v1.16b,#1
        eor     v3.16b,v3.16b,v6.16b
        st1     {v3.4s},[x2],#16
        b.eq    .Ldone

        dup     v6.4s,v3.s[3]           // just splat
        ext     v5.16b,v0.16b,v4.16b,#12
        aese    v6.16b,v0.16b

        eor     v4.16b,v4.16b,v5.16b
        ext     v5.16b,v0.16b,v5.16b,#12
        eor     v4.16b,v4.16b,v5.16b
        ext     v5.16b,v0.16b,v5.16b,#12
        eor     v4.16b,v4.16b,v5.16b

        eor     v4.16b,v4.16b,v6.16b
        b       .Loop256

.Ldone:
        str     w12,[x2]
        mov     x3,#0

.Lenc_key_abort:
        mov     x0,x3                   // return value
        ldr     x29,[sp],#16
        ret
.size   aes_v8_set_encrypt_key,.-aes_v8_set_encrypt_key

/*
 * extern void aes_cbc_01(const unsigned char *inp, unsigned char *out,
 *			size_t length, const AES_KEY *key,
 *			unsigned char *ivp, const int enc);
 */
	.globl	aes_cbc_01
	.type	aes_cbc_01,%function
	.align	5
aes_cbc_01:
	stp	x29,x30,[sp,#-16]!
	add	x29,sp,#0
	subs	x2,x2,#16
	mov	x8,#16
	b.lo	.Lcbc_abort
	csel	x8,xzr,x8,eq

	cmp	w5,#0			// en- or decrypting?
	// aes_key.rounds is filled in w5 now
	ldr	w5,[x3,#240]
	and	x2,x2,#-16
	// load iv
	ld1	{v6.16b},[x4]
	// load ptext
	ld1	{v0.16b},[x0],x8

	// aes_key.rd_key is 60x32 bits long (240 bytes long)
	# V16 is used as rk0 in initial
	ld1	{v16.4s,v17.4s},[x3]		// load key schedule...
	// key(128-bit) --> rounds(10)
	// key(192-bit) --> rounds(12)
	// key(256-bit) --> rounds(14)
	// aes_key.rounds = 6 + key_length (bytes) / 4;
	sub	w5,w5,#6
	// x5: key_length (bytes) / 4
	// x7: x3 + key_length * 4
	// key_length (16: 128-bit), x5: rk4
	// key_length (24: 192-bit), x5: rk6
	// key_length (32: 256-bit), x5: rk8
	add	x7,x3,x5,lsl#4	// pointer to last 7 round keys
	// w5: key_length / 4 - 2
	// key(128-bit) --> w5(2)
	// key(192-bit) --> w5(4)
	// key(256-bit) --> w5(6)
	sub	w5,w5,#2
	ld1	{v18.4s,v19.4s},[x7],#32
	ld1	{v20.4s,v21.4s},[x7],#32
	ld1	{v22.4s,v23.4s},[x7],#32
	ld1	{v7.4s},[x7]

	add	x7,x3,#32
	mov	w6,w5
	b.eq	.Lcbc_dec

	cmp	w5,#2
	# in = in XOR iv
	eor	v0.16b,v0.16b,v6.16b
	# what's this???
	# why rk0 XOR rk10 for 128-bit?
	# why rk0 XOR rk14 for 256-bit?
	eor	v5.16b,v16.16b,v7.16b
	b.eq	.Lcbc_enc128

	ld1	{v2.4s,v3.4s},[x7]
	# x7: points to rk1
	add	x7,x3,#16
	# x6: points to rk4
	add	x6,x3,#16*4
	# x12: points to rk5
	add	x12,x3,#16*5
	aese	v0.16b,v16.16b
	aesmc	v0.16b,v0.16b
	# x14: points to rk6
	add	x14,x3,#16*6
	# x3: points to rk7
	add	x3,x3,#16*7
	b	.Lenter_cbc_enc

.align	4
.Loop_cbc_enc:
	# rk0/next block of ptext
	aese	v0.16b,v16.16b
	aesmc	v0.16b,v0.16b
	st1	{v6.16b},[x1],#16
.Lenter_cbc_enc:
	# rk1
	aese	v0.16b,v17.16b
	aesmc	v0.16b,v0.16b
	# rk2
	aese	v0.16b,v2.16b
	aesmc	v0.16b,v0.16b
	# V16(rk0/ptext) is replaced by rk4
	ld1	{v16.4s},[x6]
	cmp	w5,#4
	# rk3
	aese	v0.16b,v3.16b
	aesmc	v0.16b,v0.16b
	# V17(rk1) is replaced by rk5
	ld1	{v17.4s},[x12]
	b.eq	.Lcbc_enc192

	# rk4 (256b)
	aese	v0.16b,v16.16b
	aesmc	v0.16b,v0.16b
	# V16(rk0/rk4) is replaced by rk6
	ld1	{v16.4s},[x14]
	# rk5 (256b)
	aese	v0.16b,v17.16b
	aesmc	v0.16b,v0.16b
	# V17(rk1/rk5) is replaced by rk7
	ld1	{v17.4s},[x3]
	nop

.Lcbc_enc192:
	# rk6 (256b)
	aese	v0.16b,v16.16b
	aesmc	v0.16b,v0.16b
	subs	x2,x2,#16
	# rk7 (256b)
	aese	v0.16b,v17.16b
	aesmc	v0.16b,v0.16b
	csel	x8,xzr,x8,eq
	# rk8 (256b)
	aese	v0.16b,v18.16b
	aesmc	v0.16b,v0.16b
	# rk9 (256b)
	aese	v0.16b,v19.16b
	aesmc	v0.16b,v0.16b
	# V16(rk0/rk4/rk6) is replaced by the next block of ptext
	ld1	{v16.16b},[x0],x8
	# rk10 (256b)
	aese	v0.16b,v20.16b
	aesmc	v0.16b,v0.16b
	eor	v16.16b,v16.16b,v5.16b
	# rk11 (256b)
	aese	v0.16b,v21.16b
	aesmc	v0.16b,v0.16b
	# V17 is used. So load rk1 again into V17.
	ld1	{v17.4s},[x7]		// re-pre-load rndkey[1]
	# rk12 (256b)
	aese	v0.16b,v22.16b
	aesmc	v0.16b,v0.16b
	# rk13 (256b)
	aese	v0.16b,v23.16b
	eor	v6.16b,v0.16b,v7.16b
	b.hs	.Loop_cbc_enc

	st1	{v6.16b},[x1],#16
	b	.Lcbc_done

.align	5
.Lcbc_enc128:
	ld1	{v2.4s,v3.4s},[x7]
	aese	v0.16b,v16.16b
	aesmc	v0.16b,v0.16b
	b	.Lenter_cbc_enc128
.Loop_cbc_enc128:
	aese	v0.16b,v16.16b
	aesmc	v0.16b,v0.16b
	st1	{v6.16b},[x1],#16
.Lenter_cbc_enc128:
	aese	v0.16b,v17.16b
	aesmc	v0.16b,v0.16b
	subs	x2,x2,#16
	aese	v0.16b,v2.16b
	aesmc	v0.16b,v0.16b
	csel	x8,xzr,x8,eq
	aese	v0.16b,v3.16b
	aesmc	v0.16b,v0.16b
	aese	v0.16b,v18.16b
	aesmc	v0.16b,v0.16b
	aese	v0.16b,v19.16b
	aesmc	v0.16b,v0.16b
	# V16 is changed from rk0 to the next block of ptext
	# V0 (the first block of ptext) is in use. So pre-load the next
	# block into another V register.
	ld1	{v16.16b},[x0],x8
	aese	v0.16b,v20.16b
	aesmc	v0.16b,v0.16b
	aese	v0.16b,v21.16b
	aesmc	v0.16b,v0.16b
	aese	v0.16b,v22.16b
	aesmc	v0.16b,v0.16b
	# Why XOR between the next block of ptext and V5?
	# V5: XOR between the first block of ptext and the last block of key
	eor	v16.16b,v16.16b,v5.16b
	aese	v0.16b,v23.16b
	eor	v6.16b,v0.16b,v7.16b
	b.hs	.Loop_cbc_enc128

	st1	{v6.16b},[x1],#16
	b	.Lcbc_done

.align	5
.Lcbc_dec:
	ld1	{v24.16b},[x0],#16
	subs	x2,x2,#32		// bias
	add	w6,w5,#2
	orr	v3.16b,v0.16b,v0.16b
	orr	v1.16b,v0.16b,v0.16b
	orr	v27.16b,v24.16b,v24.16b
	b.lo	.Lcbc_dec_tail

	orr	v1.16b,v24.16b,v24.16b
	ld1	{v24.16b},[x0],#16
	orr	v2.16b,v0.16b,v0.16b
	orr	v3.16b,v1.16b,v1.16b
	orr	v27.16b,v24.16b,v24.16b
	cmp	x2,#32
	b.lo	.Loop3x_cbc_dec

	ld1	{v25.16b},[x0],#16
	ld1	{v26.16b},[x0],#16
	sub	x2,x2,#32		// bias
	mov	w6,w5
	orr	v28.16b,v25.16b,v25.16b
	orr	v29.16b,v26.16b,v26.16b

.Loop5x_cbc_dec:
	aesd	v0.16b,v16.16b
	aesimc	v0.16b,v0.16b
	aesd	v1.16b,v16.16b
	aesimc	v1.16b,v1.16b
	aesd	v24.16b,v16.16b
	aesimc	v24.16b,v24.16b
	aesd	v25.16b,v16.16b
	aesimc	v25.16b,v25.16b
	aesd	v26.16b,v16.16b
	aesimc	v26.16b,v26.16b
	ld1	{v16.4s},[x7],#16
	subs	w6,w6,#2
	aesd	v0.16b,v17.16b
	aesimc	v0.16b,v0.16b
	aesd	v1.16b,v17.16b
	aesimc	v1.16b,v1.16b
	aesd	v24.16b,v17.16b
	aesimc	v24.16b,v24.16b
	aesd	v25.16b,v17.16b
	aesimc	v25.16b,v25.16b
	aesd	v26.16b,v17.16b
	aesimc	v26.16b,v26.16b
	ld1	{v17.4s},[x7],#16
	b.gt	.Loop5x_cbc_dec

	aesd	v0.16b,v16.16b
	aesimc	v0.16b,v0.16b
	aesd	v1.16b,v16.16b
	aesimc	v1.16b,v1.16b
	aesd	v24.16b,v16.16b
	aesimc	v24.16b,v24.16b
	aesd	v25.16b,v16.16b
	aesimc	v25.16b,v25.16b
	aesd	v26.16b,v16.16b
	aesimc	v26.16b,v26.16b
	cmp	x2,#0x40		// because .Lcbc_tail4x
	sub	x2,x2,#0x50

	aesd	v0.16b,v17.16b
	aesimc	v0.16b,v0.16b
	aesd	v1.16b,v17.16b
	aesimc	v1.16b,v1.16b
	aesd	v24.16b,v17.16b
	aesimc	v24.16b,v24.16b
	aesd	v25.16b,v17.16b
	aesimc	v25.16b,v25.16b
	aesd	v26.16b,v17.16b
	aesimc	v26.16b,v26.16b
	csel	x6,xzr,x2,gt		// borrow x6, w6, "gt" is not typo
	mov	x7,x3

	aesd	v0.16b,v18.16b
	aesimc	v0.16b,v0.16b
	aesd	v1.16b,v18.16b
	aesimc	v1.16b,v1.16b
	aesd	v24.16b,v18.16b
	aesimc	v24.16b,v24.16b
	aesd	v25.16b,v18.16b
	aesimc	v25.16b,v25.16b
	aesd	v26.16b,v18.16b
	aesimc	v26.16b,v26.16b
	add	x0,x0,x6		// x0 is adjusted in such way that
					// at exit from the loop v1.16b-v26.16b
					// are loaded with last "words"
	add	x6,x2,#0x60		// because .Lcbc_tail4x

	aesd	v0.16b,v19.16b
	aesimc	v0.16b,v0.16b
	aesd	v1.16b,v19.16b
	aesimc	v1.16b,v1.16b
	aesd	v24.16b,v19.16b
	aesimc	v24.16b,v24.16b
	aesd	v25.16b,v19.16b
	aesimc	v25.16b,v25.16b
	aesd	v26.16b,v19.16b
	aesimc	v26.16b,v26.16b

	aesd	v0.16b,v20.16b
	aesimc	v0.16b,v0.16b
	aesd	v1.16b,v20.16b
	aesimc	v1.16b,v1.16b
	aesd	v24.16b,v20.16b
	aesimc	v24.16b,v24.16b
	aesd	v25.16b,v20.16b
	aesimc	v25.16b,v25.16b
	aesd	v26.16b,v20.16b
	aesimc	v26.16b,v26.16b

	aesd	v0.16b,v21.16b
	aesimc	v0.16b,v0.16b
	aesd	v1.16b,v21.16b
	aesimc	v1.16b,v1.16b
	aesd	v24.16b,v21.16b
	aesimc	v24.16b,v24.16b
	aesd	v25.16b,v21.16b
	aesimc	v25.16b,v25.16b
	aesd	v26.16b,v21.16b
	aesimc	v26.16b,v26.16b

	aesd	v0.16b,v22.16b
	aesimc	v0.16b,v0.16b
	aesd	v1.16b,v22.16b
	aesimc	v1.16b,v1.16b
	aesd	v24.16b,v22.16b
	aesimc	v24.16b,v24.16b
	aesd	v25.16b,v22.16b
	aesimc	v25.16b,v25.16b
	aesd	v26.16b,v22.16b
	aesimc	v26.16b,v26.16b

	eor	v4.16b,v6.16b,v7.16b
	aesd	v0.16b,v23.16b
	eor	v5.16b,v2.16b,v7.16b
	ld1	{v2.16b},[x0],#16
	aesd	v1.16b,v23.16b
	eor	v17.16b,v3.16b,v7.16b
	ld1	{v3.16b},[x0],#16
	aesd	v24.16b,v23.16b
	eor	v30.16b,v27.16b,v7.16b
	ld1	{v27.16b},[x0],#16
	aesd	v25.16b,v23.16b
	eor	v31.16b,v28.16b,v7.16b
	ld1	{v28.16b},[x0],#16
	aesd	v26.16b,v23.16b
	orr	v6.16b,v29.16b,v29.16b
	ld1	{v29.16b},[x0],#16
	cbz	x6,.Lcbc_tail4x
	ld1	{v16.4s},[x7],#16	// re-pre-load rndkey[0]
	eor	v4.16b,v4.16b,v0.16b
	orr	v0.16b,v2.16b,v2.16b
	eor	v5.16b,v5.16b,v1.16b
	orr	v1.16b,v3.16b,v3.16b
	eor	v17.16b,v17.16b,v24.16b
	orr	v24.16b,v27.16b,v27.16b
	eor	v30.16b,v30.16b,v25.16b
	orr	v25.16b,v28.16b,v28.16b
	eor	v31.16b,v31.16b,v26.16b
	st1	{v4.16b},[x1],#16
	orr	v26.16b,v29.16b,v29.16b
	st1	{v5.16b},[x1],#16
	mov	w6,w5
	st1	{v17.16b},[x1],#16
	ld1	{v17.4s},[x7],#16	// re-pre-load rndkey[1]
	st1	{v30.16b},[x1],#16
	st1	{v31.16b},[x1],#16
	b.hs	.Loop5x_cbc_dec

	add	x2,x2,#0x50
	cbz	x2,.Lcbc_done

	add	w6,w5,#2
	subs	x2,x2,#0x30
	orr	v0.16b,v27.16b,v27.16b
	orr	v2.16b,v27.16b,v27.16b
	orr	v1.16b,v28.16b,v28.16b
	orr	v3.16b,v28.16b,v28.16b
	orr	v24.16b,v29.16b,v29.16b
	orr	v27.16b,v29.16b,v29.16b
	b.lo	.Lcbc_dec_tail

	b	.Loop3x_cbc_dec

.align	4
.Lcbc_tail4x:
	eor	v5.16b,v4.16b,v1.16b
	eor	v17.16b,v17.16b,v24.16b
	eor	v30.16b,v30.16b,v25.16b
	eor	v31.16b,v31.16b,v26.16b
	st1	{v5.16b},[x1],#16
	st1	{v17.16b},[x1],#16
	st1	{v30.16b},[x1],#16
	st1	{v31.16b},[x1],#16

	b	.Lcbc_done
.align	4
.Loop3x_cbc_dec:
	aesd	v0.16b,v16.16b
	aesimc	v0.16b,v0.16b
	aesd	v1.16b,v16.16b
	aesimc	v1.16b,v1.16b
	aesd	v24.16b,v16.16b
	aesimc	v24.16b,v24.16b
	ld1	{v16.4s},[x7],#16
	subs	w6,w6,#2
	aesd	v0.16b,v17.16b
	aesimc	v0.16b,v0.16b
	aesd	v1.16b,v17.16b
	aesimc	v1.16b,v1.16b
	aesd	v24.16b,v17.16b
	aesimc	v24.16b,v24.16b
	ld1	{v17.4s},[x7],#16
	b.gt	.Loop3x_cbc_dec

	aesd	v0.16b,v16.16b
	aesimc	v0.16b,v0.16b
	aesd	v1.16b,v16.16b
	aesimc	v1.16b,v1.16b
	aesd	v24.16b,v16.16b
	aesimc	v24.16b,v24.16b
	eor	v4.16b,v6.16b,v7.16b
	subs	x2,x2,#0x30
	eor	v5.16b,v2.16b,v7.16b
	csel	x6,x2,x6,lo			// x6, w6, is zero at this point
	aesd	v0.16b,v17.16b
	aesimc	v0.16b,v0.16b
	aesd	v1.16b,v17.16b
	aesimc	v1.16b,v1.16b
	aesd	v24.16b,v17.16b
	aesimc	v24.16b,v24.16b
	eor	v17.16b,v3.16b,v7.16b
	add	x0,x0,x6		// x0 is adjusted in such way that
					// at exit from the loop v1.16b-v24.16b
					// are loaded with last "words"
	orr	v6.16b,v27.16b,v27.16b
	mov	x7,x3
	aesd	v0.16b,v20.16b
	aesimc	v0.16b,v0.16b
	aesd	v1.16b,v20.16b
	aesimc	v1.16b,v1.16b
	aesd	v24.16b,v20.16b
	aesimc	v24.16b,v24.16b
	ld1	{v2.16b},[x0],#16
	aesd	v0.16b,v21.16b
	aesimc	v0.16b,v0.16b
	aesd	v1.16b,v21.16b
	aesimc	v1.16b,v1.16b
	aesd	v24.16b,v21.16b
	aesimc	v24.16b,v24.16b
	ld1	{v3.16b},[x0],#16
	aesd	v0.16b,v22.16b
	aesimc	v0.16b,v0.16b
	aesd	v1.16b,v22.16b
	aesimc	v1.16b,v1.16b
	aesd	v24.16b,v22.16b
	aesimc	v24.16b,v24.16b
	ld1	{v27.16b},[x0],#16
	aesd	v0.16b,v23.16b
	aesd	v1.16b,v23.16b
	aesd	v24.16b,v23.16b
	ld1	{v16.4s},[x7],#16	// re-pre-load rndkey[0]
	add	w6,w5,#2
	eor	v4.16b,v4.16b,v0.16b
	eor	v5.16b,v5.16b,v1.16b
	eor	v24.16b,v24.16b,v17.16b
	ld1	{v17.4s},[x7],#16	// re-pre-load rndkey[1]
	st1	{v4.16b},[x1],#16
	orr	v0.16b,v2.16b,v2.16b
	st1	{v5.16b},[x1],#16
	orr	v1.16b,v3.16b,v3.16b
	st1	{v24.16b},[x1],#16
	orr	v24.16b,v27.16b,v27.16b
	b.hs	.Loop3x_cbc_dec

	cmn	x2,#0x30
	b.eq	.Lcbc_done
	nop

.Lcbc_dec_tail:
	aesd	v1.16b,v16.16b
	aesimc	v1.16b,v1.16b
	aesd	v24.16b,v16.16b
	aesimc	v24.16b,v24.16b
	ld1	{v16.4s},[x7],#16
	subs	w6,w6,#2
	aesd	v1.16b,v17.16b
	aesimc	v1.16b,v1.16b
	aesd	v24.16b,v17.16b
	aesimc	v24.16b,v24.16b
	ld1	{v17.4s},[x7],#16
	b.gt	.Lcbc_dec_tail

	aesd	v1.16b,v16.16b
	aesimc	v1.16b,v1.16b
	aesd	v24.16b,v16.16b
	aesimc	v24.16b,v24.16b
	aesd	v1.16b,v17.16b
	aesimc	v1.16b,v1.16b
	aesd	v24.16b,v17.16b
	aesimc	v24.16b,v24.16b
	aesd	v1.16b,v20.16b
	aesimc	v1.16b,v1.16b
	aesd	v24.16b,v20.16b
	aesimc	v24.16b,v24.16b
	cmn	x2,#0x20
	aesd	v1.16b,v21.16b
	aesimc	v1.16b,v1.16b
	aesd	v24.16b,v21.16b
	aesimc	v24.16b,v24.16b
	eor	v5.16b,v6.16b,v7.16b
	aesd	v1.16b,v22.16b
	aesimc	v1.16b,v1.16b
	aesd	v24.16b,v22.16b
	aesimc	v24.16b,v24.16b
	eor	v17.16b,v3.16b,v7.16b
	aesd	v1.16b,v23.16b
	aesd	v24.16b,v23.16b
	b.eq	.Lcbc_dec_one
	eor	v5.16b,v5.16b,v1.16b
	eor	v17.16b,v17.16b,v24.16b
	orr	v6.16b,v27.16b,v27.16b
	st1	{v5.16b},[x1],#16
	st1	{v17.16b},[x1],#16
	b	.Lcbc_done

.Lcbc_dec_one:
	eor	v5.16b,v5.16b,v24.16b
	orr	v6.16b,v27.16b,v27.16b
	st1	{v5.16b},[x1],#16

.Lcbc_done:
	st1	{v6.16b},[x4]
.Lcbc_abort:
	ldr	x29,[sp],#16
	ret
.size	aes_cbc_01,.-aes_cbc_01
