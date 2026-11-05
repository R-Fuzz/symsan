// METADATA: lib_small_arg_deref.yaml
// ENV: checker_nullderef
// CFLAGS: -mllvm -ucsan-abilist=%S/metadata/lib_small_arg.abilist
// LIB: lib_small_arg_lib.c
// FLAG: 153

/*
 * The other side of lib_small_arg: an unlabeled value in the null range that
 * a library callee does dereference faults there, and the fault is reported
 * as the null dereference, at the call.
 */
int lib_deref(const int *p);

int cal(int n)
{
	volatile long word = 0x30;
	return lib_deref((const int *)word) + n;
}
