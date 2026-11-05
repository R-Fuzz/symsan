/* library code: a value it only compares (cppgc's TryFindNode), and one it
   dereferences */
int lib_in_range(const void *p, const void *lo, const void *hi)
{
	return lo <= p && p < hi;
}

int lib_deref(const int *p)
{
	return *p;
}
