#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>

void exact_sleep_seconds(int seconds);

int main()
{
    int pid = getpid();
    printf("PID = %d\n", pid);
    while (1)
    {
        puts("running in a loop");
        exact_sleep_seconds(1);
    }
}

void exact_sleep_seconds(int seconds)
{
    struct timespec req, rem;

    // Set initial sleep duration to 1 second, 0 nanoseconds
    req.tv_sec = seconds;
    req.tv_nsec = 0;

    // Loop until nanosleep succeeds without being interrupted by a signal
    while (nanosleep(&req, &rem) == -1)
    {
        if (errno == EINTR)
        {
            // Interrupted by a signal! Update req with the remaining time and try again.
            req = rem;
        }
        else
        {
            // A different error occurred (rare for nanosleep, but good practice to handle)
            perror("nanosleep failed");
            break;
        }
    }
}
