#include <stdio.h>
#include <arpa/inet.h>
#pragma pack(1)
struct A 
{ 
        char t:4; 
        char k:4; 
        int  i:8; 
        int  m:8; 
}; 

int main()
{
    short i = 10;
    short m = htons(i);

    printf("i = %d\n", i);
    printf("m = %d\n", m);

    printf("sizeof(A) = %d\n", sizeof(A));
}

#pragma pack()
