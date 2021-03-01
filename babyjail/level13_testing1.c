#define _GNU_SOURCE 1
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
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

int child_pid;

void cleanup(int signal)
{
    kill(child_pid, 9);
    kill(getpid(), 9);
}

int main(int argc, char **argv)
{
    printf("[+] Welcome to %s!\n", argv[0]);
    puts("[+] This challenge will fork into a jail.");
    puts("[+] Inside of this child process jail, you will only be able");
    puts("[+] to communicate with the parent process.");
    puts("[+] If you want the flag, you must convince the parent process");
    puts("[+] to give it to you.");

    for (int i = 3; i < 10000; i++) close(i);

    int file_descriptors[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, file_descriptors) == 0);
    int parent_socket = file_descriptors[0];
    int child_socket = file_descriptors[1];

    alarm(1);
    signal(SIGALRM, cleanup);

    child_pid = fork();
    if (!child_pid)
    {
        close(0);
        close(1);
        close(2);
        close(parent_socket);

        void *shellcode_mem = mmap((void *)0x1337000, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANON, 0, 0);
        assert(shellcode_mem == (void *)0x1337000);

        scmp_filter_ctx ctx;

        ctx = seccomp_init(SCMP_ACT_KILL);
        assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0) == 0);
        assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0) == 0);
        assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0) == 0);

        assert(seccomp_load(ctx) == 0);

        read(child_socket, shellcode_mem, 1024);
        ((void(*)())shellcode_mem)();
        exit(0);
    }

    else
    {
        char shellcode[1024];
        read(0, shellcode, 1024);

        write(parent_socket, shellcode, 1024);

        while (1)
        {
            char child_command[128] = { 0 };
            int command_length = read(parent_socket, child_command, 128);

            // break up the command into the operation and the argument by putting a null byte where
            // the ":" should be.
            child_command[9] = '\0';
            // everything from the 10th byte onwards is the argument
            char *command_argument = child_command + 10;
            command_length -= 10;

            if (strcmp(child_command, "print_msg") == 0)
            {
                puts(command_argument);
            }
            else if (strcmp(child_command, "read_file") == 0)
            {
                sendfile(parent_socket, open(command_argument, 0), 0, 128);
            }
            else
            {
                // unknown command
            }
        }
    }
}
