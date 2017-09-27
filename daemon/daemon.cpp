#include <unistd.h>
#include <iostream>

int main()
{
	daemon(0,1);

	while(1)
	{
		std::cout<<"_________"<<std::endl;
		sleep(1);
	}	
	return 0;
}
