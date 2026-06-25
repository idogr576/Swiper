#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#include "socket.h"
#include "../utils.h"

#define LISTEN_BACKLOG 50

#define PORTNUM 1234

int g_socket = -1;

int socket_init()
{
    g_socket = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    if (g_socket < 0)
    {
        perror("");
        return 1;
    }
    struct sockaddr_in addr = {.sin_family = AF_INET, .sin_port = htons(PORTNUM), .sin_addr = INADDR_ANY};
    bind(g_socket, (struct sockaddr *)&addr, sizeof(addr));
    LOG_DEBUG("[MODULE] Done socket module init\n");
    return 0;
}

int socket_iterate()
{
    char buff[BUFSIZ] = {0};
    struct sockaddr src_addr;
    socklen_t addrlen;

    size_t bytes = recvfrom(g_socket, buff, sizeof(buff), 0, &src_addr, &addrlen);
    if (bytes == -1)
    {
        return 1;
    }
    PRINT("received %ld bytes: %s\n", bytes, buff);
    return 0;
}

int socket_destroy()
{
    close(g_socket);
    LOG_DEBUG("[FIN] socket module\n");
    return 0;
}