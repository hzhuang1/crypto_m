
	.arch armv8.2-a+sve

.macro xxh32_sve_save_stack
        stp     x29, x30, [sp, -48]!
        mov     x29, sp
.endm

.macro xxh32_sve_restore_stack
        mov     sp, x29
        ldp     x29, x30, [sp], #48
.endm

// The step of seed is 16-byte.
.macro xxh32_init_seed_index  idx:req, t:req
        mov     \t, 16
        index   \idx\().s, #0, \t
.endm

// The step of data is 256-byte.
.macro xxh32_init_data_index  idx:req, t:req
        mov     \t, 256
        index   \idx\().s, #0, \t
.endm

// rotate left
// Accessed Predicate registers: p0
// Accessed 8 Z registers
.macro xxh32_rtl_x4  v1:req, v2:req, v3:req, v4:req, t1:req, t2:req, t3:req, t4:req, bits:req
        lsl     \t1\().s, \v1\().s, \bits
        lsl     \t2\().s, \v2\().s, \bits
        lsl     \t3\().s, \v3\().s, \bits
        lsl     \t4\().s, \v4\().s, \bits
        lsr     \v1\().s, p0/m, \v1\().s, 32 - \bits
        lsr     \v2\().s, p0/m, \v2\().s, 32 - \bits
        lsr     \v3\().s, p0/m, \v3\().s, 32 - \bits
        lsr     \v4\().s, p0/m, \v4\().s, 32 - \bits
        orr     \v1\().s, p0/m, \v1\().s, \t1\().s
        orr     \v2\().s, p0/m, \v2\().s, \t2\().s
        orr     \v3\().s, p0/m, \v3\().s, \t3\().s
        orr     \v4\().s, p0/m, \v4\().s, \t4\().s
.endm

// round
// Accessed Predicate register: p0
// Accessed 10 Z registers
.macro xxh32_round_x4  v1:req, v2:req, v3:req, v4:req, in1:req, in2:req, in3:req, in4:req, prm1:req, prm2:req
        // seed += in * PRIM32_2; 
        mla     \v1\().s, p0/m, \in1\().s, \prm2\().s
        mla     \v2\().s, p0/m, \in2\().s, \prm2\().s
        mla     \v3\().s, p0/m, \in3\().s, \prm2\().s
        mla     \v4\().s, p0/m, \in4\().s, \prm2\().s
        xxh32_rtl_x4  \v1, \v2, \v3, \v4, \in1, \in2, \in3, \in4, 13
        // seed *= PRIME32_1
        mul     \v1\().s, p0/m, \v1\().s, \prm1\().s
        mul     \v2\().s, p0/m, \v2\().s, \prm1\().s
        mul     \v3\().s, p0/m, \v3\().s, \prm1\().s
        mul     \v4\().s, p0/m, \v4\().s, \prm1\().s
.endm

// Allocate two memory blocks. One is for seed buffer, and the other is for
// data buffer.
// Param job_vec is read-only in the macro.
// Param seed_buf, data_buf, tmp are updated in the macro.
.macro xxh32_alloc_on_stack  job_cnt:req, seed_buf:req, data_buf:req, tmp:req
        // Reserve the unified seed buffer for all data lanes.
        // Each lane costs 16-byte long.
        mov     \tmp, \job_cnt, lsl #4
        sub     \seed_buf, sp, \tmp
        // Reserve the unified data buffer for all data lanes.
        // Each lane costs 256-byte long.
        mov     \tmp, \job_cnt, lsl #8
        sub     \data_buf, \seed_buf, \tmp
        sub     \data_buf, \data_buf, \tmp
        mov     sp, \data_buf
.endm

// Load seed from jobs into a single memory block
// Param job_vec, job_cnt, buffer are read-only in the macro.
// Param src, dst, tmp and cnt are updated in the macro.
.macro xxh32_load_seed_from_jobs  job_vec:req, job_cnt, buffer:req, src:req, dst:req, tmp:req, cnt:req
        // Avoid to use jobs and buffer directly. Since it may be used
        // in multiple times.
        mov     \src, \job_vec
        mov     \dst, \buffer
        mov     \cnt, \job_cnt
110:
        // tmp: ranges from jobs[0], jobs[1], ...
        ldr     \tmp, [\src], #8
        // tmp: jobs[1].digest, ranges from 0, ...
        add     \tmp, \tmp, #16
        // Read 128-bit seed value
        ld1     {v7.16b}, [\tmp]
        // Save 128-bit seed value in the continous buffer
        st1     {v7.16b}, [\dst], #16
        subs    \cnt, \cnt, #1
        bne     110b
.endm

// Load data from jobs into a single memory block
.macro xxh32_load_data_from_jobs  job_vec:req, job_cnt, block_idx:req, buffer:req, src:req, dst:req, tmp:req, cnt:req
        // Avoid to use jobs and buffer directly. Since it may be used
        // in multiple times.
        mov     \src, \job_vec
        mov     \dst, \buffer
        mov     \cnt, \job_cnt
120:
        // tmp: ranges from jobs[0], jobs[1], ...
        ldr     \tmp, [\src], #8
        // tmp: jobs[i].buffer, ranges from 0, ...
        ldr     \tmp, [\tmp]
        // tmp: block address in job[i].buffer (offset: 256-byte)
        add     \tmp, \tmp, \block_idx, lsl #8
        mov     x13, #256
121:
        ldr     x12, [\tmp], 8
        str     x12, [\dst], 8
        subs    x13, x13, 8
        bne     121b
        subs    \cnt, \cnt, 1
        bne     120b
.endm

.macro xxh32_save_seed_to_jobs  job_vec:req, job_cnt, buffer:req, src:req, dst:req, tmp:req, cnt:req
        // Avoid to use jobs and buffer directly. Since it may be used
        // in multiple times.
        mov     \src, \buffer
        mov     \dst, \job_vec
        mov     \cnt, \job_cnt
130:
        // tmp: ranges from jobs[0], jobs[1], ...
        ldr     \tmp, [\dst], 8
        // tmp: jobs[i].digest, ranges from 0, ...
        add     \tmp, \tmp, 16
        ld1     {v7.16b}, [\src], 16
        st1     {v7.16b}, [\tmp]
        subs    \cnt, \cnt, 1
        bne     130b
.endm

// Load sparse seed or data from a single memory block into vector registers.
// Param buf and idx are read-only in the macro.
// Param tmp, in1, in2, in3, in4 are updated in the macro.
// Accessed predicate registers: p0
.macro xxh32_sparse_load  buf:req, idx:req, in1:req, in2:req, in3:req, in4:req, tmp:req
        mov     \tmp, \buf
        ld1w    \in1\().s, p0/z, [\tmp, \idx\().s, UXTW 0]
        add     \tmp, \tmp, #4
        ld1w    \in2\().s, p0/z, [\tmp, \idx\().s, UXTW 0]
        add     \tmp, \tmp, #4
        ld1w    \in3\().s, p0/z, [\tmp, \idx\().s, UXTW 0]
        add     \tmp, \tmp, #4
        ld1w    \in4\().s, p0/z, [\tmp, \idx\().s, UXTW 0]
        add     \tmp, \tmp, #4
.endm

// Save sparse seed or data from vector registers to a single memory block.
// Param buf, idx, in1, in2, in3, in4 are read-only in the macro.
// Param tmp is updated in the macro.
.macro xxh32_sparse_save  buf:req, idx:req, in1:req, in2:req, in3:req, in4:req, tmp:req
        mov     \tmp, \buf
        st1w    \in1\().s, p0, [\tmp, \idx\().s, UXTW 0]
        add     \tmp, \tmp, #4
        st1w    \in2\().s, p0, [\tmp, \idx\().s, UXTW 0]
        add     \tmp, \tmp, #4
        st1w    \in3\().s, p0, [\tmp, \idx\().s, UXTW 0]
        add     \tmp, \tmp, #4
        st1w    \in4\().s, p0, [\tmp, \idx\().s, UXTW 0]
        add     \tmp, \tmp, #4
.endm

// Compute seed for one block data
// Param buf, prm1, prm2, didx are read-only in the macro.
// Param s1, s2, s3, s4, in1, in2, in3, in4 are updated in the macro.
.macro xxh32_single  job_vec:req, job_cnt:req, blk_idx:req, buf:req, didx:req, prm1:req, prm2:req, s1:req, s2:req, s3:req, s4:req, in1:req, in2:req, in3:req, in4:req, src:req, dst:req, tmp:req, cnt:req
        xxh32_load_data_from_jobs  \job_vec, \job_cnt, \blk_idx, \buf, \src, \dst, \tmp, \cnt
        mov     \cnt, #16
	mov	\dst, \buf
150:
        // load data
        xxh32_sparse_load  \dst, \didx, \in1, \in2, \in3, \in4, \tmp
	mov	\dst, \tmp
        xxh32_round_x4  \s1, \s2, \s3, \s4, \in1, \in2, \in3, \in4, \prm1, \prm2
        subs    \cnt, \cnt, #1
        bne     150b
.endm

// void xxh32_mb_sve(XXH32_JOB **job_vec, int job_cnt, int blocks)
        .global xxh32_mb_sve
        .type xxh32_mb_sve, %function
xxh32_mb_sve:
        xxh32_sve_save_stack
        cbz     x2, 90f

        // x4: seed_buf in stack
        // x5: data_buf in stack
        xxh32_alloc_on_stack  x1, x4, x5, x6

        // x1/w1: job_cnt
        whilelo p0.s, wzr, w1

        adr     x8, XXH32_PRIME
        // Z0: XXH32_PRIME32_1
        ldr     x6, [x8], 4
        mov     z0.s, p0/m, w6
        // Z1: XXH32_PRIME32_2
        ldr     x6, [x8]
        mov     z1.s, p0/m, w6
        // Z2: seed index
        // Z12: data index
        xxh32_init_seed_index z2, w6
        xxh32_init_data_index z12, w6

        xxh32_load_seed_from_jobs  x0, x1, x4, x7, x8, x6, x10
        // Load sparse seeds into vector registers.
        xxh32_sparse_load  x4, z2, z3, z4, z5, z6, x6

        // x11: block index
        mov     x11, #0
10:
        xxh32_single  x0, x1, x11, x5, z12, z0, z1, z3, z4, z5, z6, z7, z8, z9, z10, x7, x8, x6, x10
        add     x11, x11, #1
        cmp     x11, x2
        bne     10b
	ptrue	p1.b
	st1b	z3.b, p1, [x3]
	add	x3, x3, 16
	st1b	z4.b, p1, [x3]
	add	x3, x3, 16
	st1b	z5.b, p1, [x3]
	add	x3, x3, 16
	st1b	z6.b, p1, [x3]
	add	x3, x3, 16
	//b	90f

        // Save sparse seeds from vector registers to a memory block.
        xxh32_sparse_save  x4, z2, z3, z4, z5, z6, x6
        // Save sparse seeds back into job_vec.
        xxh32_save_seed_to_jobs x0, x1, x4, x7, x8, x6, x10
90:
        xxh32_sve_restore_stack
        ret
        .size xxh32_mb_sve, .-xxh32_mb_sve


        .section .rodata.cst16,"aM",@progbits,16
        .align 16

XXH32_PRIME:
        .word   0x9E3779B1      // PRIME32_1
        .word   0x85EBCA77      // PRIME32_2
        .word   0xC2B2AE3D      // PRIME32_3
        .word   0x27D4E82F      // PRIME32_4
        .word   0x165667B1      // PRIME32_5

