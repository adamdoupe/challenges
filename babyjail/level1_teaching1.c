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

    puts("[+] The only thing you can do in this challenge is read out one single file, as specified by");
    puts("[+] the first argument to the program (argv[1]). Make it count.");

    puts("[!] Let's get started!");

    assert(argc > 1);

    puts("[.] Creating the jail");

    char jail_path[] = "/tmp/jail-XXXXXX";
    assert(mkdtemp(jail_path) != NULL);

    printf("[.] chroot()ing into the jail in %s\n", jail_path);
    assert(chroot(jail_path) == 0);

    puts("[.] Creating the fake /flag");
    int fffd = open("/flag", O_WRONLY | O_CREAT);
    write(fffd, "FLAG{FAKE}", 10);
    close(fffd);

    printf("[.] Reading requested file (%s)\n", argv[1]);
    sendfile(1, open(argv[1], 0), 0, 128);

}
