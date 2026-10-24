// METADATA: asm_cal.yaml
// ENV: KO_CHECKER_UBI
// FLAG: 1

#include <stdlib.h>

struct opts {
	int stamp;
	unsigned short saw : 1, ok : 1, dsack : 1, wscale_ok : 1, sack : 3,
		smc : 1, snd : 4, rcv : 4;
	unsigned char unknown : 1, unused : 7;
	unsigned char num;
};

int cal(int doff)
{
	struct opts o;

	o.saw = 0;
	if (o.unknown && doff == 9)
		exit(201);
	return 0;
}
