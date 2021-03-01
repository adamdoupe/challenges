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

    puts("[+] This challenge will chroot into a jail in /tmp/jail-XXXXXX.");
    puts("[+] You will be able to easily read a fake flag file inside this jail,");
    puts("[+] not the real flag file outside of it.");
    puts("[+] If you want the real flag, you must escape.");

    puts("[+] For extra security, this challenge will only allow certain system calls!");

    puts("[!] Let's get started!");

    assert(argc > 1);

    assert(strstr(argv[1], "flag") == NULL);

    int fd = open(argv[1], O_NOFOLLOW);

    char jail_path[] = "/tmp/jail-XXXXXX";
    assert(mkdtemp(jail_path) != NULL);

    assert(chroot(jail_path) == 0);

    assert(chdir("/") == 0);

    int fffd = open("/flag", O_WRONLY | O_CREAT);
    write(fffd, "FLAG{FAKE}", 10);
    close(fffd);

    void *shellcode_addr = mmap((void *)0x1337000, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANON, 0, 0);
    assert((unsigned char *)shellcode_addr == (unsigned char *)0x1337000);

    int actual_size = read(0, shellcode_addr, 0x1000);

    scmp_filter_ctx ctx;
    ctx = seccomp_init(SCMP_ACT_KILL);
    assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(openat), 0) == 0);
    assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0) == 0);
    assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0) == 0);
    assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sendfile), 0) == 0);
    assert(seccomp_load(ctx) == 0);

    ((void(*)())shellcode_addr)();
}
