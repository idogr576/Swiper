#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <signal.h>

#include "injector.h"
#include "utils.h"

void welcome_message(char *path);

int main(int argc, char *argv[])
{
    if (argc != 3)
    {
        PRINT("Usage: %s <PID> <SO Path>\n", argv[0]);
        return 1;
    }
    pid_t pid = atoi(argv[1]);
    if (errno)
    {
        goto cleanup;
    }
    g_so_path = strdup(argv[2]);
    char cmdline[BUFSIZ] = {0};
    char cmdlinePath[BUFSIZ] = {0};
    FILE *fp = NULL;

    snprintf(cmdlinePath, sizeof(cmdlinePath), "/proc/%d/cmdline", pid);
    fp = fopen(cmdlinePath, "r");
    if (!fp)
    {
        LOG_INFO("could not open file: %s\n", cmdlinePath);
        goto cleanup;
    }
    welcome_message("swiper.msg");
    fread(cmdline, 1, sizeof(cmdline), fp);
    LOG_INFO("Intercepting PID %d: %s\n", pid, cmdline);

    state_t remote_state = {.pid = pid, .n = g_shellcode_bin_len};
    state_t *pstate = &remote_state;

    if (remote_attach_process(pstate))
    {
        LOG_INFO("cannot attach to remote process\n");
        goto cleanup;
    }
    time_t start_time = time(NULL);

    uintptr_t p = remote_libc_start_address(pstate);
    LOG_DEBUG("libc start address is %#lx\n", p);

    remote_state_preserve(pstate);
    LOG_DEBUG("stopped remote process at %#llx\n", remote_state.regs.rip);

    remote_alloc_args_on_stack(pstate);

    LOG_DEBUG("using resolved addresses to build a shellcode\n");
    construct_shellcode(pstate);

    remote_write_shellcode(pstate);

    remote_run_shellcode(pstate);
    LOG_DEBUG("state restored... detaching\n");

    ptrace(PTRACE_DETACH, pid, 0, 0);

    time_t end_time = time(NULL);
    LOG_DEBUG("remote process was stopped for %ld seconds in total\n", end_time - start_time);

cleanup:
    if (fp)
        fclose(fp);
    if (g_so_path)
        free(g_so_path);
    if (!errno)
        perror("");
    return 0;
}

void welcome_message(char *path)
{
    FILE *fp = fopen(path, "r");
    if (!fp)
        return;
    char buff[BUFSIZ];
    fread(buff, 1, sizeof(buff), fp);
    PRINT("%s\n", buff);
}