#include <stdio.h>

/*
compile with:
    gcc -shared -fPIC injected.c -o libinjected.so
*/

void __attribute__((constructor)) entrypoint(void)
{
    printf("[INJECTED] Shared object loaded successfully!\n");
}
