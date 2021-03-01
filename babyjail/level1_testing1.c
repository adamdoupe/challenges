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

int main(int argc, char **argv)
{
    printf("[+] Welcome to %s!\n", argv[0]);

    puts("[+] This challenge will chroot into a jail in /tmp/jail-XXXXXX.");
    puts("[+] You will be able to easily read a fake flag file inside this jail,");
    puts("[+] not the real flag file outside of it.");
    puts("[+] If you want the real flag, you must escape.");

    puts("[!] Let's get started!");

    assert(argc > 1);

    char jail_path[] = "/tmp/jail-XXXXXX";
    assert(mkdtemp(jail_path) != NULL);

    assert(chroot(jail_path) == 0);

    int fffd = open("/flag", O_WRONLY | O_CREAT);
    write(fffd, "FLAG{FAKE}", 10);
    close(fffd);

    printf("[.] Reading requested file (%s)\n", argv[1]);
    sendfile(1, open(argv[1], 0), 0, 128);

}
