#include <iostream>

struct test
{
    int i;
    char buf[];

};

int main()
{
    int size = sizeof(test);
    std::cout<<"size = "<<size<<std::endl;
    

}
