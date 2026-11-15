/* The parts of the port that only need BSD sockets, and so are the same on an ESP32 and a PC. */
#include "cz_port.h"

#include <stdio.h>
#include <string.h>

#if defined(_WIN32)
#define CZ_ERRNO WSAGetLastError()
#define CZ_EINPROGRESS WSAEWOULDBLOCK
#define CZ_EWOULDBLOCK WSAEWOULDBLOCK
#else
#define CZ_ERRNO errno
#define CZ_EINPROGRESS EINPROGRESS
#define CZ_EWOULDBLOCK EWOULDBLOCK
#endif

bool cz_socket_set_nonblocking(int fd)
{
#if defined(_WIN32)
    u_long on = 1;
    return ioctlsocket((SOCKET)fd, FIONBIO, &on) == 0;
#else
    int flags = fcntl(fd, F_GETFL, 0);
    return flags >= 0 && fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
#endif
}

void cz_socket_close(int fd)
{
    if (fd < 0) {
        return;
    }
#if defined(_WIN32)
    closesocket((SOCKET)fd);
#else
    close(fd);
#endif
}

bool cz_socket_would_block(void)
{
    int error = CZ_ERRNO;
#if defined(_WIN32)
    return error == WSAEWOULDBLOCK;
#else
    return error == EWOULDBLOCK || error == EAGAIN || error == EINTR;
#endif
}

bool cz_resolve(const char *host, uint32_t *address)
{
    struct addrinfo hints;
    struct addrinfo *found = NULL;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, NULL, &hints, &found) != 0 || found == NULL) {
        return false;
    }
    *address = ((struct sockaddr_in *)found->ai_addr)->sin_addr.s_addr;
    freeaddrinfo(found);
    return true;
}

int cz_tcp_connect(const char *host, uint16_t port, int timeout_ms)
{
    struct sockaddr_in target;
    memset(&target, 0, sizeof target);
    target.sin_family = AF_INET;
    target.sin_port = htons(port);
    if (!cz_resolve(host, &target.sin_addr.s_addr)) {
        return -1;
    }

    int fd = (int)socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd < 0) {
        return -1;
    }
    cz_socket_set_nonblocking(fd);
    if (connect(fd, (struct sockaddr *)&target, sizeof target) != 0) {
        int error = CZ_ERRNO;
        if (error != CZ_EINPROGRESS && error != CZ_EWOULDBLOCK) {
            cz_socket_close(fd);
            return -1;
        }
        fd_set writable;
        fd_set failed;
        FD_ZERO(&writable);
        FD_ZERO(&failed);
        FD_SET(fd, &writable);
        FD_SET(fd, &failed);
        struct timeval wait = { timeout_ms / 1000, (timeout_ms % 1000) * 1000 };
        int pending = 0;
        cz_socklen size = sizeof pending;
        if (select(fd + 1, NULL, &writable, &failed, &wait) <= 0 || getsockopt(fd, SOL_SOCKET, SO_ERROR, (char *)&pending, &size) != 0 || pending != 0) {
            cz_socket_close(fd);
            return -1;
        }
    }
    int on = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (const char *)&on, sizeof on);
    return fd;
}
