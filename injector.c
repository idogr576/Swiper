#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>

#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <signal.h>

#define BACKUP_SIZE 50

// TODO: find the offset dynamically given the libc.so path
#define DLOPEN_OFFSET_LIBC 0x00000000000981f0

#define SAFETY_BUF_SIZE 0x1000

// TODO: find this path dynamically using /proc/PID/maps
#define LIBC_SO_PATH "/usr/lib/x86_64-linux-gnu/libc.so.6"

#define INJECTED_SO_PATH "/home/ido/Desktop/work/so-injectior/libinjected.so"

// for debug
#include <unistd.h>
void fin() { return; }

typedef unsigned long long int reg_t;

typedef struct State
{
    struct
    {
        uintptr_t addr;
        uint8_t val;
    } patched_bytes[BUFSIZ];
    int n; // number of patched bytes
    struct user_regs_struct regs;
    uintptr_t libc_addr;
    uintptr_t argv_addr;
} State;

size_t remote_malloc(int pid, void *addr, uint8_t *buff, size_t n);
int remote_attach_process(int pid);
int remote_state_preserve(int pid, State *state);
int remote_alloc_args_on_stack(int pid, State *state);
int remote_write_shellcode(int pid, State *state);
int remote_run_shellcode(int pid, State *state);

uintptr_t remote_libc_start_address(int pid, State *state);

int main(int argc, char *argv[])
{
    if (argc != 2)
    {
        printf("Usage: %s <PID>\n", argv[0]);
        return 1;
    }
    int pid = atoi(argv[1]);
    if (errno)
    {
        perror("");
        return 2;
    }
    char cmdline[BUFSIZ] = {0};
    char cmdlinePath[BUFSIZ] = {0};
    FILE *fp = NULL;

    snprintf(cmdlinePath, sizeof(cmdlinePath), "/proc/%d/cmdline", pid);
    fp = fopen(cmdlinePath, "r");
    if (!fp)
    {
        printf("could not open file: %s\n", cmdlinePath);
    }
    fread(cmdline, 1, sizeof(cmdline), fp);
    printf("Intercepting PID %d: %s\n", pid, cmdline);

    if (remote_attach_process(pid))
    {
        printf("cannot attach to remote process\n");
        return 3;
    }

    State remote_state = {0};
    remote_state_preserve(pid, &remote_state);
    printf("stopped remote process at %#llx\n", remote_state.regs.rip);

    remote_alloc_args_on_stack(pid, &remote_state);

    uintptr_t p = remote_libc_start_address(pid, &remote_state);
    printf("libc start address is %#lx\n", p);

    remote_write_shellcode(pid, &remote_state);

    remote_run_shellcode(pid, &remote_state);
    printf("state restored... detaching\n");

    // ptrace(PTRACE_DETACH, pid, NULL, (void *)SIGSTOP);
    ptrace(PTRACE_DETACH, pid, 0, 0);

    return 0;
}

size_t remote_malloc(int pid, void *addr, uint8_t *buff, size_t n)
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

int remote_attach_process(int pid)
{
    int wstatus;
    ptrace(PTRACE_ATTACH, pid, NULL, NULL);
    waitpid(pid, &wstatus, 0);
    if (!WIFSTOPPED(wstatus))
    {
        printf("remote process did not stop as expected\n");
        return 1;
    }
    return 0;
}

int remote_state_preserve(int pid, State *state)
{
    if (ptrace(PTRACE_GETREGS, pid, NULL, &state->regs) == -1)
    {
        perror("");
        errno;
    }

    reg_t ip = state->regs.rip;
    state->n = 0;

    for (int i = 0; i < BACKUP_SIZE; i++)
    {
        uint8_t byte = (uint8_t)ptrace(PTRACE_PEEKDATA, pid, (void *)(ip + i), NULL);
        state->patched_bytes[i].addr = ip + i;
        state->patched_bytes[i].val = byte;
        state->n++;
    }
    return 0;
}

int remote_alloc_args_on_stack(int pid, State *state)
{
    /*
    this function set up necessary allocations for dlopen call.
    the stack start from top to bottom - allocate on lower addresses than $rsp.
    plus, take a safety buffer for allocations by future call to dlopen on the same stack.
    */
    uintptr_t stack_end = (uintptr_t)state->regs.rsp;
    uintptr_t alloc_start = stack_end - SAFETY_BUF_SIZE;

    const char *so_path = INJECTED_SO_PATH;

    union
    {
        uint8_t byte;
        void *p;
    } data = {0};

    printf("allocating " INJECTED_SO_PATH " in address %#lx\n", alloc_start);
    for (int i = 0; i < strlen(so_path); i++)
    {
        data.byte = so_path[i];
        ptrace(PTRACE_POKEDATA, pid, (void *)(alloc_start + i), data);
    }
    state->argv_addr = alloc_start;
    return 0;
}

uintptr_t remote_libc_start_address(int pid, State *state)
{
    char mapsPath[BUFSIZ] = {0};
    char line[BUFSIZ] = {0};
    char *sep;
    uintptr_t base_addr = 0;

    snprintf(mapsPath, sizeof(mapsPath), "/proc/%d/maps", pid);
    FILE *fp = fopen(mapsPath, "r");

    do
    {
        if (!fgets(line, sizeof(line), fp))
        {
            perror("");
            return 1;
        }
        if (strstr(line, LIBC_SO_PATH))
        {
            // 7020cda00000-7020cda28000 r--p 00000000 103:05 661671 /usr/lib/x86_64-linux-gnu/libc.so.6
            sep = strchr(line, '-');
            if (!sep)
            {
                printf("error parsing the process libc start address\n");
                return 2;
            }
            *sep = '\0';
            base_addr = (uintptr_t)strtoull(line, NULL, 16);
        }
    } while (!base_addr);

    state->libc_addr = base_addr;
    return base_addr;
}

int remote_write_shellcode(int pid, State *state)
{
    /* this shellcode is generated with:
        nasm -f bin shellcode.asm -o shellcode.bin
        xxd -i shellcode.bin

    BITS 64
    mov rdi, 0xffffffffffff ; place holder address for so allocated path mov rsi, 0x1            ; RTLD_LAZY
    mov rax, 0xeeeeeeeeeeee ; place holder address for dlopen
    call rax

    */
    unsigned char shellcode_bin[] = {
        0x48, 0xbf, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, // mov rdi, 0xffffffffffff
        0xbe, 0x01, 0x00, 0x00, 0x00,                               // mov rsi, 0x1 ; RTLD_LAZY
        0x48, 0xb8, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0x00, 0x00, // mov rax, 0xeeeeeeeeeeee
        0xff, 0xd0,                                                 // call rax
        0xcc                                                        // int 0x3
    };
    unsigned int shellcode_bin_len = 28;

    /*
    first, write the proper addresses to the shellcode
        so str: [2:7]
        dlopen: [17:22]
    */

    const uintptr_t argv_addr = state->argv_addr;
    const uintptr_t dlopen_addr = state->libc_addr + DLOPEN_OFFSET_LIBC;

    unsigned char *conv_argv = (unsigned char *)&argv_addr;
    unsigned char *conv_dlopen = (unsigned char *)&dlopen_addr;
    for (int i = 0; i < 6; i++) // 12 digits
    {
        shellcode_bin[i + 2] = conv_argv[i];
        shellcode_bin[i + 17] = conv_dlopen[i];
    }

    // write the shellcode to the current instruction pointed address
    reg_t ip = state->regs.rip;

    union
    {
        uint8_t byte;
        void *p;
    } data = {0};

    printf("writing shellcode in address %#llx\n", ip);
    for (int i = 0; i < shellcode_bin_len; i++)
    {
        data.byte = shellcode_bin[i];
        ptrace(PTRACE_POKEDATA, pid, (void *)(ip + i), data);
    }

    return shellcode_bin_len;
}

int remote_run_shellcode(int pid, State *state)
{
    struct user_regs_struct regs = {0};
    int wstatus;
    do
    {
        printf("send SIGCONT to process\n");
        ptrace(PTRACE_CONT, pid, 0, 0);
        waitpid(pid, &wstatus, 0);
        if (!WIFSTOPPED(wstatus))
        {
            printf("did not stop as expected\n");
            return 1;
        }
        ptrace(PTRACE_GETREGS, pid, 0, &regs);
    } while (regs.rip != state->regs.rip + 28);
    printf("reached end of injected shellcode\n");

    printf("restoring patched bytes\n");
    uint8_t *buff = (uint8_t *)malloc(state->n * sizeof(uint8_t));
    for (int i = 0; i < state->n; i++)
    {
        buff[i] = state->patched_bytes[i].val;
    }
    remote_malloc(pid, (void *)state->patched_bytes[0].addr, buff, state->n);

    printf("restoring old registers values\n");
    ptrace(PTRACE_SETREGS, pid, 0, &state->regs);

    printf("preserve listen on remote process\n");
    // ptrace(PTRACE_CONT, pid, 0, 0);
    return 0;
}