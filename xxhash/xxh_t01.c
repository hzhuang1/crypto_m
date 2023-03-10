/* This test case is used to use xxhash */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
/* Without XXH_INLINE_ALL, there's an error on XXH64_state_t. */
#ifndef XXH_INLINE_ALL
#  define XXH_INLINE_ALL
#endif
#include <xxhash.h>

#define CMD_LENGTH      256
#define SRC_FILE	"/tmp/x"

/* The algorithm sequence is same as defined in xxhsum */
enum {
	TYPE_XXH32 = 0,
	TYPE_XXH64,
	TYPE_XXH128,
	TYPE_XXH3,
	TYPE_XXH_UNKNOWN,
};

struct buffer {
	void *addr;
	size_t len;
	FILE *fp;
};

static int check_file(char *file)
{
	FILE *fp;

	if (!file)
		return -EINVAL;
	/* test whether the file could be open */
	fp = fopen(file, "r");
	if (!fp)
		return -ENFILE;
	fclose(fp);
	return 0;
}

static int load_entire_file(char *file, struct buffer *buf)
{
	FILE *fp;
	struct stat stat_buf;
	int ret;
	size_t sz;

	if (!file || !buf)
		return -EINVAL;
	/* get file length */
	ret = stat(file, &stat_buf);
	if (ret < 0) {
		fprintf(stderr, "Fail to get file stat (%d)!\n", ret);
		return ret;
	}
	fp = fopen(file, "r");
	if (!fp) {
		fprintf(stderr, "Fail to open file!\n");
		return -ENFILE;
	}
	buf->addr = malloc(stat_buf.st_size);
	if (!buf->addr) {
		fprintf(stderr, "Fail to allocate memory!\n");
		ret = -ENOMEM;
		goto out;
	}
	buf->len = stat_buf.st_size;
	sz = fread(buf->addr, sizeof(char), stat_buf.st_size, fp);
	if (!sz) {
		fprintf(stderr, "Fail to read file!\n");
		ret = -EFAULT;
		goto out_rd;
	}
	return 0;
out_rd:
	free(buf->addr);
	buf->addr = NULL;
	buf->len = 0;
out:
	fclose(fp);
	return ret;
}

static int load_partial_file(char *file, struct buffer *buf, int split)
{
	FILE *fp;
	struct stat stat_buf;
	int ret;
	size_t sz, buf_sz;

	if (!file || !buf || (split <= 0))
		return -EINVAL;
	/* get file length */
	ret = stat(file, &stat_buf);
	if (ret < 0) {
		fprintf(stderr, "Fail to get file stat (%d)!\n", ret);
		return ret;
	}
	if (stat_buf.st_size < split) {
		fprintf(stderr, "File length (%ld) is less than split (%d)\n",
			stat_buf.st_size, split);
		return ret;
	}
	buf_sz = (stat_buf.st_size + split - 1) / split;
	fp = fopen(file, "r");
	if (!fp) {
		fprintf(stderr, "Fail to open file!\n");
		return -ENFILE;
	}
	buf->addr = malloc(buf_sz);
	if (!buf->addr) {
		fprintf(stderr, "Fail to allocate memory!\n");
		ret = -ENOMEM;
		goto out;
	}
	buf->len = buf_sz;
	sz = fread(buf->addr, sizeof(char), buf_sz, fp);
	if (!sz) {
		fprintf(stderr, "Fail to read file!\n");
		ret = -EFAULT;
		goto out_rd;
	}
	buf->fp = fp;
	return 0;
out_rd:
	free(buf->addr);
	buf->addr = NULL;
	buf->len = 0;
out:
	fclose(fp);
	return ret;
}

void run_xxh64_01(char *file)
{
	struct buffer buf;
	XXH64_hash_t h64;
	int ret;

	ret = check_file(file);
	if (ret < 0)
		return;
	ret = load_entire_file(file, &buf);
	if (ret < 0)
		return;
	h64 = XXH64(buf.addr, buf.len, 0);
	printf("%s Hash64:%lx\n", __func__, h64);
	free(buf.addr);
}

void run_xxh64_02(char *file)
{
	struct buffer buf;
	XXH64_hash_t h64;
	XXH64_state_t state;
	int ret;

	ret = check_file(file);
	if (ret < 0)
		return;
	ret = load_entire_file(file, &buf);
	if (ret < 0)
		return;
	XXH64_reset(&state, 0);
	XXH64_update(&state, buf.addr, buf.len);
	h64 = XXH64_digest(&state);
	printf("%s Hash64:%lx\n", __func__, h64);
	free(buf.addr);
}

void run_xxh64_03(char *file)
{
	struct buffer buf;
	XXH64_hash_t h64;
	XXH64_state_t state;
	int ret, split = 4;
	size_t sz;

	ret = check_file(file);
	if (ret < 0)
		return;
	ret = load_partial_file(file, &buf, split);
	if (ret < 0)
		return;
	XXH64_reset(&state, 0);
	XXH64_update(&state, buf.addr, buf.len);
	while (--split > 0) {
		sz = fread(buf.addr, sizeof(char), buf.len, buf.fp);
		if (!sz) {
			fprintf(stderr, "Fail to read file!\n");
			ret = -EFAULT;
			goto out;
		}
		XXH64_update(&state, buf.addr, sz);
	}
	h64 = XXH64_digest(&state);
	printf("%s Hash64:%lx\n", __func__, h64);
	free(buf.addr);
	return;
out:
	free(buf.addr);
}

void run_xxhsum(char *file, int type)
{
	char *cmd_buf;

	/* invalid type */
	if ((type < TYPE_XXH32) || (type >= TYPE_XXH_UNKNOWN))
		return;
	if (check_file(file) < 0)
		return;

	cmd_buf = malloc(CMD_LENGTH);
	if (!cmd_buf) {
		fprintf(stderr, "Fail to allocate buffer!\n");
		return;
	}

	/* make sure there's always a '\0' in the command buffer. */
	memset(cmd_buf, 0, CMD_LENGTH);
	snprintf(cmd_buf, CMD_LENGTH - 1, "xxhsum -H%d %s", type, file);
	system(cmd_buf);
	free(cmd_buf);
}

int main(int argc, char **argv)
{
	run_xxhsum(SRC_FILE, TYPE_XXH64);
	run_xxh64_01(SRC_FILE);
	run_xxh64_02(SRC_FILE);
	run_xxh64_03(SRC_FILE);
	return 0;
}

