#include <assert.h>
#include <iostream>

//#define ASSERT(x) ((x) || (dbg_printf("assertion failed ("__FILE__":%d): \"%s\"\n",__LINE__,#x), break_point(), FALSE))

int main()
{
	int* p = NULL;
	ASSERT(p != NULL);
	return 0;
}
