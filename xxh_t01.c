/* This test case is used to use xxhash */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CMD_LENGTH      256

/* The algorithm sequence is same as defined in xxhsum */
enum {
	XXH32 = 0,
	XXH64,
	XXH128,
	XXH3,
	XXH_UNKNOWN,
};

void run_xxhsum(char *file, int type)
{
	char *cmd_buf;
	FILE *fp;

	/* invalid type */
	if ((type < XXH32) || (type >= XXH_UNKNOWN))
		return;
	if (!file)
		return;
	/* test whether the file could be open */
	fp = fopen(file, "r");
	if (!fp)
		return;
	fclose(fp);

	cmd_buf = malloc(CMD_LENGTH);
	if (!cmd_buf) {
		printf("Fail to allocate buffer!\n");
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
	run_xxhsum("/tmp/x", XXH64);
	return 0;
}

