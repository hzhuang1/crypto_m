#include <stdio.h>

extern int dump_cntw(void);
extern void load_01(unsigned char *buf);
extern void load_02(unsigned char *in, unsigned char *out);
extern void rev_01(unsigned char *in, unsigned char *out);

unsigned char in[256], out[256];

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

/* Call LD1W instruction (vector index) to gather load data. */
void t_load_01(void)
{
	int cntw;

	cntw = dump_cntw();
	printf("cntw:%d\n", cntw);
	set_buf(in, 0xaa, 256);
	init_buf(out, 0x55, 256);
	/* index is stored in Z0 now */
	load_01(out);
	dump_buf(out, 256);
	load_02(in, out);
	dump_buf(out, 256);
}

/* Call REVH instruction to reverse two 32-bit fields in each 64-bit field. */
void t_rev_01(void)
{
	init_buf(in, 0x37, 256);
	init_buf(out, 0x55, 256);
	rev_01(in, out);
	dump_buf(out, 256);
}

int main(void)
{
	t_rev_01();
	return 0;
}
