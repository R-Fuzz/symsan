// METADATA: asm_cal.yaml
// ENV: trace_bounds KO_RESIGN_PTRARGS
// FLAG: 200
// ABSENT: 150

/*
 * Resign follows the pointers stored in what it resigns.  fill() is out of
 * scope, so its call resigns m: an out-of-scope callee may write whatever it
 * can reach.  It reaches buf only through m.buf (as i2c_transfer reaches the
 * caller's read buffer through i2c_msg.buf, or kernel_recvmsg the address
 * buffer through msghdr.msg_name).  With m alone resigned, buf stayed
 * uninitialized and the read of it below was a UBI (150), not a byte the
 * solver can choose (200).
 */
struct msg {
	int len;
	char *buf;
};

void fill(struct msg *m)
{
	m->buf[0] = 0;
}

int cal(int n)
{
	char buf[4];
	struct msg m = { .len = sizeof(buf), .buf = buf };

	fill(&m);
	if (buf[0] == 'x')
		exit(200);
	return n;
}
