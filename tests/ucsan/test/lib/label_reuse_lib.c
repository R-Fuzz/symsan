/* calls back into in-scope code: an in-scope loop of 70000 trips is ended by
   the loop threshold */
void lib_repeat(void (*f)(void), int n)
{
	for (int i = 0; i < n; i++)
		f();
}
