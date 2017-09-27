#include <string>
#include <iostream>
#include <string.h>
#include <stdio.h>

int main()
{
    std::string str = "123";
    std::cout<<"len(str) = "<<str.length()<<std::endl;

    char buf[1024] = {0};
    strcpy(buf, str.c_str());

    printf("%s\n", buf);    

}
