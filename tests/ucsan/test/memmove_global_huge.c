// METADATA: asm_cal.yaml
// ENV: trace_bounds
// FLAG: 124 200

/*
 * An access through a pointer into a global, larger than the object size
 * limit, only had what is symbolized capped; the access kept its size.
 * rm_map_entry_at (add_map_entry) memmoves cache_map_n - idx entries, both
 * from the seed, and materialized and copied gigabytes: a hang.  It now
 * ends the run (REASON_OBJ_OOB), as for a lazily created object.
 */
#include <stdlib.h>
#include <string.h>

struct ent {
	unsigned long start, end;
};

static struct ent init_map[8];
struct ent *map = init_map;
int map_n;

int cal(int idx)
{
	map_n--;
	if (map_n > idx)
		memmove(map + idx, map + idx + 1, sizeof(*map) * (map_n - idx));
	if (idx == 7)
		exit(200);
	return 0;
}
