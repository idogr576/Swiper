#include <stdio.h>
#include <unistd.h>

int main()
{
    int pid = getpid();
    printf("PID = %d\n", pid);
    while (1)
    {
        puts("running in a loop");
        sleep(1);
    }
}