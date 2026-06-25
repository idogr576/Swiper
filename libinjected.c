/*
compile with:
gcc -shared -fPIC libinjected.c modules/modules.c modules/socket.c -o libinjected.so
*/

#include <stdio.h>
#include <signal.h>
#include <sys/time.h>
#include <unistd.h>

#include "libinjected.h"
#include "modules/modules.h"
#include "utils.h"

#define MAIN_LOOP_INTERVAL 50000

const static struct itimerval g_timer = {
    .it_interval.tv_sec = 0,
    .it_interval.tv_usec = MAIN_LOOP_INTERVAL,
    .it_value.tv_sec = 0,
    .it_value.tv_usec = MAIN_LOOP_INTERVAL};

void __attribute__((constructor)) entrypoint(void)
{
    tool_init();
}

void __attribute__((destructor)) exitpoint(void)
{
    tool_destroy();
}

void tool_main_loop(int sig)
{
    /* iterate over all loaded modules */
    for (int i = 0; i < g_num; i++)
    {
        if (g_modules[i]->is_loaded)
        {
            g_modules[i]->ops.iterate();
        }
    }
}

void tool_init()
{
    LOG_DEBUG("[INJECTED] Shared object loaded successfully!\n");

    /* init modules */
    LOG_DEBUG("g_num = %d\n", g_num);
    for (int i = 0; i < g_num; i++)
    {
        g_modules[i]->id = i;
        g_modules[i]->is_loaded = !g_modules[i]->ops.init();
    }
    LOG_DEBUG("[MODULE] Done all modules init\n");

    /* setup repetitive calls to main_loop */
    signal(SIGALRM, tool_main_loop);
    setitimer(ITIMER_REAL, &g_timer, NULL);
}

void tool_destroy()
{
    int ret = -1;
    for (int i = 0; i < g_num; i++)
    {
        if (g_modules[i]->is_loaded)
        {
            ret = g_modules[i]->ops.destroy();
        }
        LOG_DEBUG("module %d unloaded with exit code %d\n", g_modules[i]->id, ret);
    }
}