#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define xxh_rotl32(x, r) ((x << r) | (x >> (32 - r)))
#define xxh_rotl64(x, r) ((x << r) | (x >> (64 - r)))

static const uint32_t PRIME32_1 = 2654435761U;
static const uint32_t PRIME32_2 = 2246822519U;
static const uint32_t PRIME32_3 = 3266489917U;
static const uint32_t PRIME32_4 =  668265263U;
static const uint32_t PRIME32_5 =  374761393U;

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

void *init_buffer(size_t size)
{
	void *buf;

	buf = malloc(size);
	if (!buf)
		return NULL;
	init_buf(buf, 0x37 , size);
	dump_buf(buf, size);
	//memset(buf, 0xa7, size);
	return buf;
}

static uint32_t xxh32_round(uint32_t seed, const uint32_t input)
{
        seed += input * PRIME32_2;
        seed = xxh_rotl32(seed, 13);
        seed *= PRIME32_1;
        return seed;
}

uint32_t xxh32_digest(const void *input, const size_t len, const uint32_t seed)
{
        const uint8_t *p = (const uint8_t *)input;
        const uint8_t *b_end = p + len;
        uint32_t h32;

        if (len >= 16) {
                const uint8_t *const limit = b_end - 16;
                uint32_t v1 = seed + PRIME32_1 + PRIME32_2;
                uint32_t v2 = seed + PRIME32_2;
                uint32_t v3 = seed + 0;
                uint32_t v4 = seed - PRIME32_1;

                do {
                        v1 = xxh32_round(v1, *(uint32_t *)p);
                        p += 4;
                        v2 = xxh32_round(v2, *(uint32_t *)p);
                        p += 4;
                        v3 = xxh32_round(v3, *(uint32_t *)p);
                        p += 4;
                        v4 = xxh32_round(v4, *(uint32_t *)p);
                        p += 4;
                } while (p <= limit);

printf("#%s, %d, v1:0x%x, v2:0x%x, v3:0x%x, v4:0x%x, h32:0x%x\n", __func__, __LINE__, v1, v2, v3, v4, h32);
                h32 = xxh_rotl32(v1, 1) + xxh_rotl32(v2, 7) +
                        xxh_rotl32(v3, 12) + xxh_rotl32(v4, 18);
printf("#%s, %d, v1:0x%x, v2:0x%x, v3:0x%x, v4:0x%x, h32:0x%x\n", __func__, __LINE__, v1, v2, v3, v4, h32);
        } else {
                h32 = seed + PRIME32_5;
        }

        h32 += (uint32_t)len;
printf("#%s, %d, prime32_5:0x%x, h32:0x%x\n", __func__, __LINE__, PRIME32_5, h32);

        while (p + 4 <= b_end) {
                h32 += *(uint32_t *)p * PRIME32_3;
printf("#%s, %d, p:0x%x, h32:0x%x\n", __func__, __LINE__, *(uint32_t *)p, h32);
                h32 = xxh_rotl32(h32, 17) * PRIME32_4;
                p += 4;
        }

        while (p < b_end) {
                h32 += (*p) * PRIME32_5;
                h32 = xxh_rotl32(h32, 11) * PRIME32_1;
                p++;
        }

printf("#%s, %d, h32:0x%x\n", __func__, __LINE__, h32);
        h32 ^= h32 >> 15;
printf("#%s, %d, h32:0x%x\n", __func__, __LINE__, h32);
        h32 *= PRIME32_2;
printf("#%s, %d, h32:0x%x\n", __func__, __LINE__, h32);
        h32 ^= h32 >> 13;
printf("#%s, %d, h32:0x%x\n", __func__, __LINE__, h32);
        h32 *= PRIME32_3;
printf("#%s, %d, h32:0x%x\n", __func__, __LINE__, h32);
        h32 ^= h32 >> 16;
printf("#%s, %d, h32:0x%x\n", __func__, __LINE__, h32);

        return h32;
}

int main(void)
{
	void *buf;
	//size_t size = 4145;
	size_t size = 256;

	buf = init_buffer(size);
	if (!buf)
		return -ENOMEM;
	xxh32_digest(buf, size, 0);
	free(buf);
	return 0;
}
