#define _GNU_SOURCE 1
#include <sys/sendfile.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>

#include <seccomp.h>

int main(int argc, char **argv)
{
    printf("[+] Welcome to %s!\n", argv[0]);

    puts("[+] For extra security, this challenge will only allow certain system calls!");

    puts("[!] Let's get started!");

    void *shellcode_addr = mmap((void *)0x1337000, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANON, 0, 0);
    assert((unsigned char *)shellcode_addr == (unsigned char *)0x1337000);

    int actual_size = read(0, shellcode_addr, 0x1000);

    scmp_filter_ctx ctx;

    ctx = seccomp_init(SCMP_ACT_ALLOW);
    for (int i = 0; i < 512; i++)
    {
        switch (i)
        {
        case SCMP_SYS(close):
            continue;
        case SCMP_SYS(stat):
            continue;
        case SCMP_SYS(fstat):
            continue;
        case SCMP_SYS(lstat):
            continue;
        }
        assert(seccomp_rule_add(ctx, SCMP_ACT_KILL, i, 0) == 0);
    }

    seccomp_arch_add(ctx, SCMP_ARCH_X86);

    assert(seccomp_load(ctx) == 0);

    ((void(*)())shellcode_addr)();
}
