#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>

#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <signal.h>

#include "injector.h"
#include "utils.h"

/* the following shellcode is generated with:
    nasm -f bin shellcode.asm -o shellcode.bin
    xxd -i shellcode.bin

BITS 64
mov rdi, 0xffffffffffff ; place holder address for so allocated path mov rsi, 0x1            ; RTLD_LAZY
mov rax, 0xeeeeeeeeeeee ; place holder address for dlopen
call rax */
uint8_t g_shellcode_bin[] = {
    0x48, 0xbf, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, // mov rdi, 0xffffffffffff
    0xbe, 0x01, 0x00, 0x00, 0x00,                               // mov rsi, 0x1 ; RTLD_LAZY
    0x48, 0xb8, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0x00, 0x00, // mov rax, 0xeeeeeeeeeeee
    0xff, 0xd0,                                                 // call rax
    0xcc                                                        // int 0x3 (breakpoint)
};
const size_t g_shellcode_bin_len = sizeof(g_shellcode_bin);

// TODO: find the offset dynamically given the libc.so path
#define DLOPEN_OFFSET_LIBC (0x00000000000981f0)

#define SAFETY_BUF_SIZE (0x1000)

// TODO: find this path dynamically using /proc/PID/maps
#define LIBC_SO_PATH "/usr/lib/x86_64-linux-gnu/libc.so.6"
#define LIBC_KEYWORD "libc.so"

char *g_so_path = NULL;

size_t remote_write_mem(int pid, void *addr, uint8_t *buff, size_t n)
{
    union
    {
        uint8_t byte;
        void *p;
    } data = {0};

    for (size_t i = 0; i < n; i++)
    {
        data.p = (void *)ptrace(PTRACE_PEEKDATA, pid, (void *)(addr + i), 0);
        data.byte = buff[i];
        ptrace(PTRACE_POKEDATA, pid, (void *)(addr + i), data);
    }
    return 0;
}

int remote_attach_process(state_t *tracee)
{
    int wstatus;
    ptrace(PTRACE_ATTACH, tracee->pid, 0, 0);
    waitpid(tracee->pid, &wstatus, 0);
    if (!WIFSTOPPED(wstatus))
    {
        LOG_INFO("remote process did not stop as expected\n");
        return 1;
    }
    return 0;
}

int remote_state_preserve(state_t *tracee)
{
    if (ptrace(PTRACE_GETREGS, tracee->pid, 0, &tracee->regs) == -1)
    {
        perror("");
        return errno;
    }

    reg_t ip = tracee->regs.rip;

    for (int i = 0; i < tracee->n; i++)
    {
        uint8_t byte = (uint8_t)ptrace(PTRACE_PEEKDATA, tracee->pid, (void *)(ip + i), 0);
        tracee->patched_bytes[i] = byte;
    }
    return 0;
}

int remote_alloc_args_on_stack(state_t *tracee)
{
    /*
    this function set up necessary allocations for dlopen call.
    the stack start from top to bottom - allocate on lower addresses than $rsp.
    plus, take a safety buffer for allocations by future call to dlopen on the same stack.
    */
    uintptr_t stack_end = (uintptr_t)tracee->regs.rsp;
    uintptr_t alloc_start = stack_end - SAFETY_BUF_SIZE;

    LOG_INFO("allocating %s in address %#lx\n", g_so_path, alloc_start);
    // strlen does not include the '\0'
    remote_write_mem(tracee->pid, (void *)alloc_start, (uint8_t *)g_so_path, strlen(g_so_path) + 1);
    tracee->argv_addr = alloc_start;
    return 0;
}

uintptr_t remote_libc_start_address(state_t *tracee)
{
    char mapsPath[BUFSIZ] = {0};
    char line[BUFSIZ] = {0};
    char *sep;
    uintptr_t base_addr = 0;

    snprintf(mapsPath, sizeof(mapsPath), "/proc/%d/maps", tracee->pid);
    FILE *fp = fopen(mapsPath, "r");

    do
    {
        if (!fgets(line, sizeof(line), fp))
        {
            perror("");
            goto cleanup;
        }
        if (strstr(line, LIBC_KEYWORD))
        {
            // 7020cda00000-7020cda28000 r--p 00000000 103:05 661671 /usr/lib/x86_64-linux-gnu/libc.so.6
            sep = strchr(line, '-');
            if (!sep)
            {
                LOG_INFO("error parsing the process libc start address\n");
                return 2;
            }
            *sep = '\0';
            base_addr = (uintptr_t)strtoull(line, NULL, 16);
        }
    } while (!base_addr);

    tracee->libc_addr = base_addr;

cleanup:
    if (fp)
        fclose(fp);
    return base_addr;
}

int construct_shellcode(state_t *tracee)
{
    /*
    first, write the proper addresses to the shellcode
        so str: [2:7]
        dlopen: [17:22]
    */
    const uintptr_t argv_addr = tracee->argv_addr;
    const uintptr_t dlopen_addr = tracee->libc_addr + DLOPEN_OFFSET_LIBC;

    unsigned char *conv_argv = (unsigned char *)&argv_addr;
    unsigned char *conv_dlopen = (unsigned char *)&dlopen_addr;
    for (int i = 0; i < 6; i++) // 12 digits addresses
    {
        g_shellcode_bin[i + 2] = conv_argv[i];
        g_shellcode_bin[i + 17] = conv_dlopen[i];
    }
    return 0;
}

int remote_write_shellcode(state_t *tracee)
{
    void *ip = (void *)tracee->regs.rip;
    LOG_INFO("writing %ld bytes of shellcode in address %p\n", tracee->n, ip);
    remote_write_mem(tracee->pid, ip, g_shellcode_bin, tracee->n);

    return 0;
}

int remote_run_shellcode(state_t *tracee)
{
    struct user_regs_struct regs = {0};
    int wstatus;
    do
    {
        LOG_INFO("send SIGCONT to process\n");
        ptrace(PTRACE_CONT, tracee->pid, 0, 0);
        waitpid(tracee->pid, &wstatus, 0);
        if (!WIFSTOPPED(wstatus))
        {
            LOG_INFO("did not stop as expected\n");
            return 1;
        }
        ptrace(PTRACE_GETREGS, tracee->pid, 0, &regs);
    } while (regs.rip != tracee->regs.rip + g_shellcode_bin_len);
    LOG_INFO("reached end of injected shellcode\n");

    LOG_INFO("restoring patched bytes\n");
    remote_write_mem(tracee->pid, (void *)tracee->regs.rip, tracee->patched_bytes, tracee->n);

    LOG_INFO("restoring old registers values\n");
    ptrace(PTRACE_SETREGS, tracee->pid, 0, &tracee->regs);

    return 0;
}