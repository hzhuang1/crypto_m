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

#define ACCRND(acc, offset) \
do { \
    svuint64_t input_vec = svld1_u64(mask, xinput + offset);         \
    svuint64_t secret_vec = svld1_u64(mask, xsecret + offset);       \
    svuint64_t mixed = sveor_u64_x(mask, secret_vec, input_vec);     \
    svuint64_t swapped = svtbl_u64(input_vec, kSwap);                \
    svuint64_t mixed_lo = svextw_u64_x(mask, mixed);                 \
    svuint64_t mixed_hi = svlsr_n_u64_x(mask, mixed, 32);            \
 swapped = svdup_u64(0); \
    svuint64_t mul = svmad_u64_x(mask, mixed_lo, mixed_hi, swapped); \
	acc = mul; \
} while (0)
    //acc = svadd_u64_x(mask, acc, mul);                               \

void t_inner_mul_02(void)
{
        uint64_t *xacc = (uint64_t *)out;
        const uint64_t *xinput = (const uint64_t *)(const void *)in;
        const uint64_t *xsecret = (const uint64_t *)(const void *)secret;
	size_t nbStripes = 1;
        svuint64_t kSwap = sveor_n_u64_z(svptrue_b64(), svindex_u64(0, 1), 1);
        svbool_t mask = svptrue_pat_b64(SV_VL8);
	svuint64_t vacc;
        //svuint64_t vacc = svld1_u64(mask, xacc + 0);

	printf("%s:\n", __func__);
	init_buf(in, 0x37, 1024);
	set_buf(secret, 0x00, 1024);
	set_buf(out, 0, 1024);
	dump_buf(in, 128);
	dump_buf(secret, 128);
        vacc = svld1_u64(mask, xacc + 0);
        do {
             ACCRND(vacc, 0);
             xinput += 8;
             xsecret += 1;
             nbStripes--;
        } while (nbStripes != 0);

        svst1_u64(mask, xacc + 0, vacc);
	dump_buf(out, 128);
}

void t_inner_mul_03(void)
{
        uint64_t *xacc = (uint64_t *)out;
        const uint64_t *xinput = (const uint64_t *)(const void *)in;
        const uint64_t *xsecret = (const uint64_t *)(const void *)secret;
	svuint64_t input1, input2, secret1, secret2, acc1, acc2;
	svuint64_t mixed1, mixed2, mul1, mul2;
	svuint32_t uzp1, uzp2;
	svbool_t pd = svptrue_b64();
	svbool_t ps = svptrue_b32();

	printf("%s:\n", __func__);
	init_buf(in, 0x37, 1024);
	set_buf(secret, 0x00, 1024);
	set_buf(out, 0, 1024);
	dump_buf(in, 128);
	input1 = svld1_u64(pd, (uint64_t *)in);
	input2 = svld1_vnum_u64(pd, (uint64_t *)in, 1);
	secret1 = svld1_u64(pd, (uint64_t *)secret);
	secret2 = svld1_vnum_u64(pd, (uint64_t *)secret, 1);
	acc1 = svld1_u64(pd, (uint64_t *)out);
	acc2 = svld1_vnum_u64(pd, (uint64_t *)out, 1);
	mixed1 = sveor_u64_x(pd, secret1, input1);
	mixed2 = sveor_u64_x(pd, secret2, input2);
	uzp1 = svuzp1_u32(svreinterpret_u32_u64(mixed1),
			svreinterpret_u32_u64(mixed2));
	uzp2 = svuzp2_u32(svreinterpret_u32_u64(mixed1),
			svreinterpret_u32_u64(mixed2));
	input1 = svdup_u64(0);
	input2 = svdup_u64(0);
	mul1 = svdup_u64(0);
	//mul1 = svmlalt_u64(input1, uzp1, uzp2);
	mul2 = svdup_u64(0);
	mul2 = svmlalb_u64(input2, uzp1, uzp2);
/*
	acc1 = svadd_u64_x(pd, acc1, mul1);
	acc2 = svadd_u64_x(pd, acc2, mul2);
*/
	acc1 = mul1;
	acc2 = mul2;
	svst1_u64(pd, xacc, acc1);
	svst1_vnum_u64(pd, xacc, 1, acc2);
	dump_buf(out, 128);
}

int main(void)
{
	t_inner_mul_02();
	t_inner_mul_03();
	return 0;
}
