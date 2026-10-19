// METADATA: asm_cal.yaml
// FLAG: 200

/*
 * A search result compared with a pointer other than NULL --
 * vfs_parse_monolithic_sep's `value == key`, seq_buf's `lf + 1 < end` --
 * was an unsupported string comparison.  The result is now the haystack
 * pointer (its own label, stashed by strchr) plus the position, so the
 * solver places the '=' rather than moving key.
 */
#include <stdlib.h>
#include <string.h>

int cal(char *key)
{
	char *value = strchr(key, '=');

	if (value && value == key + 2)
		exit(200);
	return 0;
}
