#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

extern void uxtw_01(unsigned char *in, unsigned char *out);
extern void uxtw_02(unsigned char *in, unsigned char *out);
extern void index_01(unsigned char *out);
extern void ext_01(unsigned char *in, unsigned char *out);

unsigned char in[1024], out[1024];

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

int main(void)
{
	t_ext_01();
	return 0;
}
