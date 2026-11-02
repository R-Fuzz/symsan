// METADATA: lib_store_ptr_label.yaml
// ENV: trace_bounds
// CFLAGS: -mllvm -ucsan-abilist=%S/metadata/lib_store_ptr_label.abilist
// FLAG: 200 152

/*
 * Library code (grow, bump: listed uninstrumented, TaintPass's alone)
 * writes no UCSan labels; a store of it keeps the label already in the
 * slot, for a pointer it only moved.  grow() stores a new block's pointer
 * over the in-scope malloc's: the old 16-byte block's label stayed, and
 * cal's in-bounds b.p[40] was an OOB (absl's raw_hash_set, library code
 * under a v8 UT, resizing its table).  The label is kept only for a pointer
 * into its object: bump() moves the pointer within the block, and the
 * overflow past it is still caught.
 *
 * All paths must be reached:
 *   *a == 7:   grow, b.p[40] in the new 64-byte block   -> exit(200)
 *   *a == 1:   bump by 4, b.p[14] past the 16-byte block -> OOB (152)
 */
#include <stdlib.h>

struct box { char *p; };

__attribute__((noinline)) void grow(struct box *b) { b->p = malloc(64); }
__attribute__((noinline)) void bump(struct box *b) { b->p += 4; }

int cal(int *a) {
    struct box b;
    b.p = malloc(16);
    if (*a == 7) {
        grow(&b);
        b.p[40] = 1;
        if (b.p[40] == 1)
            exit(200);
    } else if (*a == 1) {
        bump(&b);
        b.p[14] = 1;
    }
    return 0;
}
