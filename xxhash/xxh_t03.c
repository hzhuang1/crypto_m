
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define xxh_rotl32(x, r) ((x << r) | (x >> (32 - r)))
#define xxh_rotl64(x, r) ((x << r) | (x >> (64 - r)))

static const uint64_t PRIME64_1 = 11400714785074694791ULL;
static const uint64_t PRIME64_2 = 14029467366897019727ULL;
static const uint64_t PRIME64_3 =  1609587929392839161ULL;
static const uint64_t PRIME64_4 =  9650029242287828579ULL;
static const uint64_t PRIME64_5 =  2870177450012600261ULL;

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
	//memset(buf, 0x37, size);
	//dump_buf(buf, size);
	return buf;
}

static uint64_t xxh64_round(uint64_t acc, const uint64_t input)
{
        acc += input * PRIME64_2;
        acc = xxh_rotl64(acc, 31);
        acc *= PRIME64_1;
        return acc;
}

static uint64_t xxh64_merge_round(uint64_t acc, uint64_t val)
{
        val = xxh64_round(0, val);
        acc ^= val;
        acc = acc * PRIME64_1 + PRIME64_4;
        return acc;
}

uint64_t xxh64(const void *input, const size_t len, const uint64_t seed)
{
        const uint8_t *p = (const uint8_t *)input;
        const uint8_t *const b_end = p + len;
        uint64_t h64;

        if (len >= 32) {
                const uint8_t *const limit = b_end - 32;
                uint64_t v1 = seed + PRIME64_1 + PRIME64_2;
                uint64_t v2 = seed + PRIME64_2;
                uint64_t v3 = seed + 0;
                uint64_t v4 = seed - PRIME64_1;

                do {
printf("%d, v1:0x%lx, v2:0x%lx, v3:0x%lx, v4:0x%lx\n", __LINE__, v1, v2, v3, v4);
printf("p:0x%lx\n", *(uint64_t *)p);
                        v1 = xxh64_round(v1, *(uint64_t *)p);
printf("round 1 (%d), v1:0x%lx, v2:0x%lx, v3:0x%lx, v4:0x%lx\n", __LINE__, v1, v2, v3, v4);
                        p += 8;
                        v2 = xxh64_round(v2, *(uint64_t *)p);
                        p += 8;
                        v3 = xxh64_round(v3, *(uint64_t *)p);
                        p += 8;
                        v4 = xxh64_round(v4, *(uint64_t *)p);
                        p += 8;
                } while (p <= limit);

printf("%d, v1:0x%lx, v2:0x%lx, v3:0x%lx, v4:0x%lx\n", __LINE__, v1, v2, v3, v4);
                h64 = xxh_rotl64(v1, 1) + xxh_rotl64(v2, 7) +
                        xxh_rotl64(v3, 12) + xxh_rotl64(v4, 18);
                h64 = xxh64_merge_round(h64, v1);
                h64 = xxh64_merge_round(h64, v2);
                h64 = xxh64_merge_round(h64, v3);
                h64 = xxh64_merge_round(h64, v4);
printf("%d, h64:0x%lx\n", __LINE__, h64);
        } else {
                h64  = seed + PRIME64_5;
        }

        h64 += (uint64_t)len;

        while (p + 8 <= b_end) {
                const uint64_t k1 = xxh64_round(0, *(uint64_t *)p);

                h64 ^= k1;
                h64 = xxh_rotl64(h64, 27) * PRIME64_1 + PRIME64_4;
                p += 8;
        }

        if (p + 4 <= b_end) {
                h64 ^= (uint64_t)(*(uint32_t *)p) * PRIME64_1;
                h64 = xxh_rotl64(h64, 23) * PRIME64_2 + PRIME64_3;
                p += 4;
        }

        while (p < b_end) {
                h64 ^= (*p) * PRIME64_5;
                h64 = xxh_rotl64(h64, 11) * PRIME64_1;
                p++;
        }

        h64 ^= h64 >> 33;
        h64 *= PRIME64_2;
        h64 ^= h64 >> 29;
        h64 *= PRIME64_3;
        h64 ^= h64 >> 32;

        return h64;
}


int main(void)
{
	void *buf;
	//size_t size = 4145;
	size_t size = 256 + 16;

	buf = init_buffer(size);
	if (!buf)
		return -ENOMEM;
	xxh64(buf, size, 0);
	free(buf);
	return 0;
}
