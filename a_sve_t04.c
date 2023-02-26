#include <arm_neon.h>
#include <arm_sve.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

extern void uxtw_01(unsigned char *in, unsigned char *out);
extern void uxtw_02(unsigned char *in, unsigned char *out);
extern void index_01(unsigned char *out);
extern void ext_01(unsigned char *in, unsigned char *out);
extern void unzip_01(unsigned char *in, unsigned char *out);
extern void inner_mul_01(unsigned char *in, unsigned char *secret,
			unsigned char *out);

unsigned char in[1024], out[1024], secret[1024];

void set_buf(unsigned char *buf, unsigned char val, size_t len)
{
	for (int i = 0; i < len; i++)
		buf[i] = val;
}

void clear_buf(unsigned char *buf, size_t len)
{
	for (int i = 0; i < len; i++)
		buf[i] = 0;
}

void init_buf(unsigned char *buf, unsigned char val, size_t len)
{
	for (int i = 0; i < len; i++) {
		buf[i] = val + ((i / 8) * 0x10) + (i % 8);
	}
}

void dump_buf(unsigned char *buf, size_t len)
{
	int i;

	for (i = 0; i < len; i += 16) {
		printf("[0x%x]: %02x-%02x-%02x-%02x %02x-%02x-%02x-%02x "
			"%02x-%02x-%02x-%02x %02x-%02x-%02x-%02x\n",
			i, buf[i], buf[i + 1], buf[i + 2], buf[i + 3],
			buf[i + 4], buf[i + 5], buf[i + 6], buf[i + 7],
			buf[i + 8], buf[i + 9], buf[i + 10], buf[i + 11],
			buf[i + 12], buf[i + 13], buf[i + 14], buf[i + 15]);
	}
}

void t_uxtw_01(void)
{
	init_buf(in, 0x37, 1024);
	init_buf(out, 0x55, 1024);
	dump_buf(out, 256);
	uxtw_02(in, out);
	dump_buf(out, 256);
}

void t_index_01(void)
{
	init_buf(in, 0x37, 1024);
	init_buf(out, 0x55, 1024);
	dump_buf(out, 256);
	index_01(out);
	dump_buf(out, 256);
}

void t_ext_01(void)
{
	init_buf(in, 0x37, 1024);
	init_buf(out, 0x55, 1024);
	dump_buf(out, 256);
	ext_01(in, out);
	dump_buf(out, 256);
}

/*
 * All input data lanes are 64-bit long. Consider them as 32-bit long,
 * split them into two vectors. So it requires to load two vectors first.
 */
void t_unzip_01(void)
{
	printf("%s:\n", __func__);
	init_buf(in, 0x37, 1024);
	dump_buf(in, 256);
	unzip_01(in, out);
	dump_buf(out, 256);
}

/*
 * t_unzip_02() is same as t_unzip_01(). Just implement it with intrinsic code.
 */
void t_unzip_02(void)
{
	svuint64_t input1, input2;
	svuint32_t uzp1, uzp2;
	svbool_t pg = svptrue_b64();
	svbool_t p32 = svptrue_b32();

	printf("%s:\n", __func__);
	init_buf(in, 0x37, 1024);
	dump_buf(in, 256);
	input1 = svld1_u64(pg, (uint64_t *)in);
	input2 = svld1_vnum_u64(pg, (uint64_t *)in, 1);
	uzp1 = svuzp1_u32(svreinterpret_u32_u64(input1),
			svreinterpret_u32_u64(input2));
	uzp2 = svuzp2_u32(svreinterpret_u32_u64(input1),
			svreinterpret_u32_u64(input2));
	/*
	svst1_u64(pg, (uint64_t *)out, svreinterpret_u64_u32(uzp1));
	svst1_vnum_u64(pg, (uint64_t *)out, 1, svreinterpret_u64_u32(uzp2));
	*/
	svst1_u32(p32, (uint32_t *)out, uzp1);
	svst1_vnum_u32(p32, (uint32_t *)out, 1, uzp2);
	dump_buf(out, 256);
}

void t_inner_mul_01(void)
{
	svuint64_t input1, input2;
	svuint32_t uzp1, uzp2;
	svbool_t pg = svptrue_b64();
	svbool_t p32 = svptrue_b32();

	printf("%s:\n", __func__);
	init_buf(in, 0x37, 1024);
	dump_buf(in, 256);
	input1 = svld1_u64(pg, (uint64_t *)in);
	input2 = svld1_vnum_u64(pg, (uint64_t *)in, 1);
	uzp1 = svuzp1_u32(svreinterpret_u32_u64(input1),
			svreinterpret_u32_u64(input2));
	uzp2 = svuzp2_u32(svreinterpret_u32_u64(input1),
			svreinterpret_u32_u64(input2));
	input1 = svmlalt_u64(input1, uzp1, uzp2);
	input2 = svmlalb_u64(input2, uzp1, uzp2);
	svst1_u64(pg, (uint64_t *)out, input1);
	svst1_vnum_u64(pg, (uint64_t *)out, 1, input2);
	dump_buf(out, 256);
}

#if 0
#define ACCRND(acc, offset) \
do { \
    svuint64_t input_vec = svld1_u64(mask, xinput + offset);         \
	acc = input_vec; \
} while (0)
/*
    svuint64_t secret_vec = svld1_u64(mask, xsecret + offset);       \
    svuint64_t mixed = sveor_u64_x(mask, secret_vec, input_vec);     \
    svuint64_t swapped = svtbl_u64(input_vec, kSwap);                \
    svuint64_t mixed_lo = svextw_u64_x(mask, mixed);                 \
    svuint64_t mixed_hi = svlsr_n_u64_x(mask, mixed, 32);            \
 swapped = svdup_u64(0); \
    svuint64_t mul = svmad_u64_x(mask, mixed_lo, mixed_hi, swapped); \
    */
    //acc = svadd_u64_x(mask, acc, mul);                               \

#endif

void t_inner_mul_02(void)
{
	{
		printf("%s:\n", __func__);
		init_buf(in, 0x37, 1024);
		set_buf(secret, 0, 1024);
		set_buf(out, 0, 1024);
		dump_buf(in, 128);
		//dump_buf(secret, 128);
	}
        uint64_t *xacc = (uint64_t *)out;
        const uint64_t *xinput = (const uint64_t *)(const void *)in;
#if 0
        const uint64_t *xsecret = (const uint64_t *)(const void *)secret;
	size_t nbStripes = 1;
        svuint64_t kSwap = sveor_n_u64_z(svptrue_b64(), svindex_u64(0, 1), 1);
        svbool_t mask = svptrue_pat_b64(SV_VL8);
        svuint64_t vacc = svld1_u64(mask, xacc + 0);

	/*
        do {
		//vacc = svdup_u64(0x7a32);
		//vacc = input_vec;
             //ACCRND(vacc, 0);
             xinput += 8;
             xsecret += 1;
             nbStripes--;
        } while (nbStripes != 0);
	*/

        //svst1_u64(mask, xacc + 0, vacc);
		svuint64_t input_vec = svld1_u64(mask, xinput + 0);
		printf("xin:0x%lx, in:0x%lx, xacc:0x%lx, out:0x%lx\n", xinput, in, xacc, out);
		printf("xin[0]:0x%x\n", *(uint32_t *)in);
	svst1_u64(svptrue_b8(), (uint64_t *)out + 0, input_vec);
#else
        const uint64_t *xsecret = (const uint64_t *)(const void *)secret;
	size_t nbStripes = 1;
        svuint64_t kSwap = sveor_n_u64_z(svptrue_b64(), svindex_u64(0, 1), 1);
	svbool_t mask = svptrue_b64();
        svuint64_t vacc = svld1_u64(mask, xacc + 0);

	svuint64_t input_vec = svld1_u64(mask, xinput + 0);
	svuint64_t secret_vec = svld1_u64(mask, xsecret + 0);
	svuint64_t mixed = sveor_u64_x(mask, secret_vec, input_vec);
	svuint64_t swapped = svtbl_u64(input_vec, kSwap);
	svuint64_t mixed_lo = svextw_u64_x(mask, mixed);
	svuint64_t mixed_hi = svlsr_n_u64_x(mask, mixed, 32);
	//svuint64_t mul = svmad_u64_x(mask, mixed_lo, mixed_hi, secret_vec);
	svuint64_t mul = svmad_u64_x(mask, mixed_lo, mixed_hi, swapped);
	svst1_u64(mask, (uint64_t *)out + 0, mul);
#endif
	dump_buf(out, 128);
	printf("out[0]:0x%x\n", *(uint32_t *)out);
}

/*
 */
void t_inner_mul_03(void)
{
        uint64_t *xacc = (uint64_t *)out;
        const uint64_t *xinput = (const uint64_t *)(const void *)in;
        const uint64_t *xsecret = (const uint64_t *)(const void *)secret;
	svuint64_t input1, input2, secret1, secret2, acc1, acc2;
	svuint64_t mixed1, mixed2, swap1, swap2, mul1, mul2;
	svuint32_t uzp1, uzp2;
	svbool_t pd = svptrue_b64();
	svbool_t ps = svptrue_b32();

	printf("%s:\n", __func__);
	init_buf(in, 0x37, 1024);
	set_buf(secret, 0x00, 1024);
	set_buf(out, 0, 1024);
	//dump_buf(in, 128);
	input1 = svld1_u64(pd, (uint64_t *)in);
	input2 = svld1_vnum_u64(pd, (uint64_t *)in, 1);
	secret1 = svld1_u64(pd, (uint64_t *)secret);
	secret2 = svld1_vnum_u64(pd, (uint64_t *)secret, 1);
	swap1 = svext_u64(input1, input1, 1);
	swap2 = svext_u64(input2, input2, 1);
	acc1 = svld1_u64(pd, (uint64_t *)out);
	acc2 = svld1_vnum_u64(pd, (uint64_t *)out, 1);
	mixed1 = sveor_u64_x(pd, secret1, input1);
	mixed2 = sveor_u64_x(pd, secret2, input2);
	uzp1 = svuzp1_u32(svreinterpret_u32_u64(mixed1),
			svreinterpret_u32_u64(mixed2));
	uzp2 = svuzp2_u32(svreinterpret_u32_u64(mixed1),
			svreinterpret_u32_u64(mixed2));
	mul1 = svmlalb_u64(secret1, uzp1, uzp2);
	mul2 = svmlalt_u64(secret2, uzp1, uzp2);
/*
	acc1 = svadd_u64_x(pd, acc1, mul1);
	acc2 = svadd_u64_x(pd, acc2, mul2);
*/
	acc1 = mul1;
	acc2 = mul2;
	//svst1_u32(ps, xacc, uzp1);
	//svst1_vnum_u32(ps, xacc, 1, uzp2);
	svst1_u64(pd, xacc, acc1);
	svst1_vnum_u64(pd, xacc, 1, acc2);
	dump_buf(out, 128);
}

void t_inner_mul_04(void)
{
	{
		printf("%s:\n", __func__);
		init_buf(in, 0x37, 1024);
		set_buf(secret, 0, 1024);
		set_buf(out, 0, 1024);
		//dump_buf(in, 128);
	}
	uint64x2_t* const xacc = (uint64x2_t *)out;
	uint8_t const* const xinput = (const uint8_t *)in;
	uint8_t const* const xsecret = (const uint8_t *)secret;
	uint64x2_t data_vec_1 = vld1q_u64(xinput + 0);
	uint64x2_t data_vec_2 = vld1q_u64(xinput + 16);
	uint64x2_t key_vec_1 = vld1q_u64(xsecret + 0);
	uint64x2_t key_vec_2 = vld1q_u64(xsecret + 16);
	uint64x2_t data_swap_1 = vextq_u64(data_vec_1, data_vec_1, 1);
	uint64x2_t data_swap_2 = vextq_u64(data_vec_2, data_vec_2, 1);
	    data_swap_1 = key_vec_1;
	    data_swap_2 = key_vec_2;
	uint64x2_t data_key_1 = veorq_u64(data_vec_1, key_vec_1);
	uint64x2_t data_key_2 = veorq_u64(data_vec_2, key_vec_2);
	uint32x4x2_t unzipped = vuzpq_u32(
	    vreinterpretq_u32_u64(data_key_1),
	    vreinterpretq_u32_u64(data_key_2)
	);
            uint32x4_t data_key_lo = unzipped.val[0];
            uint32x4_t data_key_hi = unzipped.val[1];
            uint32x2_t data_key_lo_1 = vget_low_u32(data_key_lo);
            uint32x2_t data_key_hi_1 = vget_low_u32(data_key_hi);
            uint64x2_t sum_1 = vmlal_u32(data_swap_1, data_key_lo_1, data_key_hi_1);
            uint32x2_t data_key_lo_2 = vget_high_u32(data_key_lo);
            uint32x2_t data_key_hi_2 = vget_high_u32(data_key_hi);

            uint64x2_t sum_2 = vmlal_u32(data_swap_2, data_key_lo_2, data_key_hi_2);
	//xacc[0] = vreinterpretq_u64_u32(data_key_lo);
	//xacc[1] = vreinterpretq_u64_u32(data_key_hi);
	xacc[0] = sum_1;
	xacc[1] = sum_2;
	dump_buf(out, 128);
}

/*
typedef svuint64_t xxh_u64x2 __attribute__((arm_sve_vector_bits(128)));
typedef svuint32_t xxh_u32x4 __attribute__((arm_sve_vector_bits(128)));

void t_inner_mul_05(void)
{
	{
		printf("%s:\n", __func__);
		init_buf(in, 0x37, 1024);
		set_buf(secret, 0, 1024);
		set_buf(out, 0, 1024);
		dump_buf(in, 128);
	}
	uint64x2_t* const xacc = (uint64x2_t *)out;
	uint8_t const* const xinput = (const uint8_t *)in;
	uint8_t const* const xsecret = (const uint8_t *)secret;
	uint64x2_t data_vec = vld1q_u64(xinput);
	uint64x2_t key_vec = vld1q_u64(xsecret);
	uint64x2_t swapped = vextq_u64(data_vec, data_vec, 1);
	uint64x2_t mixed_lo = veorq_u64(data_vec, key_vec);
	uint32x4_t mixed_hi = vrev64q_u32(vreinterpretq_u32_u64(mixed_lo));
	uint64x2_t mul = (uint64x2_t)(xxh_u64x2)svmlalb_u64(
			(xxh_u64x2)swapped,
			(xxh_u32x4)mixed_lo,
			(xxh_u32x4)mixed_hi);
	xacc[0] = vreinterruptq_u32_u64(mixed_lo);
	dump_buf(out, 128);
}
*/

void t_inner_mul_05(void)
{
	{
		printf("%s:\n", __func__);
		init_buf(in, 0x37, 1024);
		set_buf(secret, 0x0, 1024);
		set_buf(out, 0, 1024);
		dump_buf(in, 128);
	}
	inner_mul_01(in, secret, out);
	dump_buf(out, 128);
}

int main(void)
{
	t_inner_mul_02();
	t_inner_mul_05();
	return 0;
}
