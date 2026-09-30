// METADATA: asm_cal.yaml
// ABSENT: 1 210 211
// FLAG: 200 201

/*
 * On-demand UCSan labels: a lazily created object larger than eager_label_size
 * (64 bytes) labels a byte only when it is first read; until then its shadow
 * holds the object's own label.
 *
 * - A pointer field read directly gets its label on demand and leads to the
 *   same child object as an eager label would (200, the child's value is
 *   solvable).
 * - A shadow copy has to label its source first.  The struct copy (a memcpy)
 *   runs before anything reads b->next, so without that the copy's shadow
 *   holds b's marker, which then names b at the copy's address: c.next and
 *   b->next become different objects and the store through one is not seen
 *   through the other (210).
 * - The same through an explicit memcpy of the pointer field alone (211).
 */
#include <stdlib.h>
#include <string.h>

struct node {
	int val;
};

struct big {
	char pad[200];
	struct node *next;
	struct node *other;
};

int cal(struct big *b, struct big *d)
{
	struct big c = *b;		/* copies b's shadow before any read */
	struct node *o;

	c.next->val = 42;
	if (b->next->val != 42)
		exit(210);

	memcpy(&o, &d->other, sizeof(o));	/* d->other never read before */
	o->val = 7;
	if (d->other->val != 7)
		exit(211);

	if (b->next->val == 42 && d->pad[3] == 'x')
		exit(201);
	if (c.pad[5] == 'q')
		exit(200);
	return 0;
}
