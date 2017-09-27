#include <unistd.h>
#include <stdio.h>


int main()
{
    char buf[1024] = {0};
    int ret = gethostname(buf, sizeof(buf));
    printf("hostname = %s\n", buf);
    
    char buf1[1024] = {0};
    ret = getdomainname(buf1, sizeof(buf1));
    printf("domainname = %s\n", buf1);

}
