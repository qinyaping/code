#include <unistd.h>
#include <memory>
#include <iostream>
using namespace std;

int foo(int* i)
{
	cout<<"i = "<<*i<<endl;
	cout<<"delete object..."<<endl;
}

int foo1(int* i)
{
	cout<<"i = "<<*i<<endl;
	cout<<"delete object..."<<__FUNCTION__<<endl;
}

int main()
{
	shared_ptr<int> ptr(new int(10), foo);
	shared_ptr<int> ptr1(new int(9));
	ptr.reset(new int(2), foo1);

	cout<<"after reset..."<<endl;	
	
	return 0;
}
