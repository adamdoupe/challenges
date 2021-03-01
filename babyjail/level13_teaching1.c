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
    puts("[+] Time is up!");
    puts("[+] Terminating the child");
    kill(child_pid, 9);
    puts("[+] Terminating the parent");
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

    puts("[+] Closing all unexpected file descriptors.");
    for (int i = 3; i < 10000; i++) close(i);

    puts("[+] Creating a \"socketpair\" that the child and parent will use to communicate.");
    puts("[+] This is a pair of file descriptors that are connected: data writte to one");
    puts("[+] can be read from the other, and vice-versa.");

    int file_descriptors[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, file_descriptors) == 0);
    int parent_socket = file_descriptors[0];
    int child_socket = file_descriptors[1];

    printf("[+] The parent side of the socketpair is FD %d\n", parent_socket);
    printf("[+] The child side of the socketpair is FD %d\n", child_socket);

    puts("[+] Testing the socketpair to give you an idea of how they work!");
    int x = 0x1234;
    int y = 0;
    write(parent_socket, &x, sizeof(int));
    read(child_socket, &y, sizeof(int));
    assert(y == 0x1234);
    x = 0x1024;
    write(child_socket, &x, sizeof(int));
    read(parent_socket, &y, sizeof(int));
    assert(x == 0x1024);

    puts("[+] Registering a cleanup function that will run 1 second from now and terminate");
    puts("[+] both the parent and child.");
    alarm(1);
    signal(SIGALRM, cleanup);

    puts("[+] Forking into a parent and child (sandbox) process!");
    child_pid = fork();
    if (!child_pid)
    {
        puts("[CHILD] The child will now close itself off from the world, except");
        puts("[CHILD] for the child side of the socketpair.");
        close(0);
        close(1);
        close(2);
        close(parent_socket);

        void *shellcode_mem = mmap((void *)0x1337000, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANON, 0, 0);
        assert(shellcode_mem == (void *)0x1337000);
        printf("[CHILD] Mapped %#x bytes for shellcode at %p\n", 0x1000, (void *)0x1337000);

        scmp_filter_ctx ctx;

        puts("[CHILD] Restricting system calls (default: kill)");
        ctx = seccomp_init(SCMP_ACT_KILL);
        printf("[CHILD] Allowing syscall: %s (number %i)\n", "read", SCMP_SYS(read));
        assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0) == 0);
        printf("[CHILD] Allowing syscall: %s (number %i)\n", "write", SCMP_SYS(write));
        assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0) == 0);
        printf("[CHILD] Allowing syscall: %s (number %i)\n", "exit", SCMP_SYS(exit));
        assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0) == 0);

        puts("[CHILD] About to apply seccomp rules: after this, all communication will");
        puts("[CHILD] be through the parent process.");
        assert(seccomp_load(ctx) == 0);

        read(child_socket, shellcode_mem, 1024);
        write(child_socket, "print_msg:Executing the shellcode. Good luck!", 128);
        ((void(*)())shellcode_mem)();
        exit(0);
    }

    else
    {
        puts("[PARENT] The parent will read in your shellcode to send to the child.");
        char shellcode[1024];
        read(0, shellcode, 1024);

        puts("[PARENT] Sending the shellcode to the child!");
        write(parent_socket, shellcode, 1024);

        while (1)
        {
            char child_command[128] = { 0 };
            puts("[PARENT] Waiting for child command...");
            int command_length = read(parent_socket, child_command, 128);

            // break up the command into the operation and the argument by putting a null byte where
            // the ":" should be.
            child_command[9] = '\0';
            // everything from the 10th byte onwards is the argument
            char *command_argument = child_command + 10;
            command_length -= 10;
            printf("PARENT: received command %.10s with an argument of %d bytes from child!\n", child_command, command_length);

            if (strcmp(child_command, "print_msg") == 0)
            {
                printf("[PARENT] Child asked us to print \"%.118s\"!\n", command_argument);
                puts(command_argument);
            }
            else if (strcmp(child_command, "read_file") == 0)
            {
                printf("[PARENT] Child asked us to read them file \"%.118s\".\n", command_argument);
                sendfile(parent_socket, open(command_argument, 0), 0, 128);
            }
            else
            {
                // unknown command
                printf("[PARENT] Unknown command received from child: %s\n", child_command);
            }
        }
    }
}
