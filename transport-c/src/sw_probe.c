#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int loopback(const struct sockaddr *sa) {
    if (sa->sa_family == AF_INET)
        return (ntohl(((const struct sockaddr_in *)sa)->sin_addr.s_addr) >> 24U) == 127U;
    if (sa->sa_family == AF_INET6)
        return IN6_IS_ADDR_LOOPBACK(&((const struct sockaddr_in6 *)sa)->sin6_addr);
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "usage: sw-probe HOST PORT\n");
        return 2;
    }
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC;
    struct addrinfo *list = NULL;
    int rc = getaddrinfo(argv[1], argv[2], &hints, &list);
    if (rc != 0) { fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rc)); return 1; }
    int connected = 0;
    for (struct addrinfo *it = list; it; it = it->ai_next) {
        if (!loopback(it->ai_addr)) continue;
        int fd = socket(it->ai_family, it->ai_socktype | SOCK_CLOEXEC, it->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, it->ai_addr, it->ai_addrlen) == 0) {
            puts("loopback TCP transport reachable (TLS is handled by sw-agentd)");
            close(fd); connected = 1; break;
        }
        close(fd);
    }
    freeaddrinfo(list);
    if (!connected) { fprintf(stderr, "probe failed or host is not loopback\n"); return 1; }
    return 0;
}
