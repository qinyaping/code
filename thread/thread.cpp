#include <sys/types.h>
 #include <sys/syscall.h>
#include <unistd.h>
#include <iostream>
#include <thread>

void print()
{
    std::cout<<syscall(SYS_gettid)<<" "<<getpid()<<std::endl;
    
}

int main()
{

 //   std::cout<<gettid()<<std::endl;
    std::cout<<syscall(SYS_gettid)<<" "<<getpid()<<std::endl;
    std::thread th(print);

    th.join();
}
