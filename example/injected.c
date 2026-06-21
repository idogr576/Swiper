#include <stdio.h>
#include <signal.h>
#include <sys/time.h>
#include <unistd.h>

/*
compile with:
    gcc -shared -fPIC injected.c -o libinjected.so
*/

#define MAIN_LOOP_INTERVAL 50000

const static struct itimerval g_timer = {
    .it_interval.tv_sec = 0,
    .it_interval.tv_usec = MAIN_LOOP_INTERVAL,
    .it_value.tv_sec = 0,
    .it_value.tv_usec = MAIN_LOOP_INTERVAL};

void __attribute__((constructor)) entrypoint(void);
void main_loop(int);

void __attribute__((constructor)) entrypoint(void)
{
    printf("[INJECTED] Shared object loaded successfully!\n");
    signal(SIGALRM, main_loop);
    setitimer(ITIMER_REAL, &g_timer, NULL);
}

void main_loop(int sig)
{
    /* TODO: implement your mega-cyber utility here */
    static size_t counter = 0;
    printf("%ld\n", ++counter);
}