/*
 * The port for a PC (Linux, macOS, Windows). It exists so that the very code that runs on the
 * chip can be tested against the real platform without one. Connections to the platform are
 * plain TCP here: a development platform on this machine speaks http and ws, and a PC that needs
 * TLS uses the .NET or the TypeScript SDK instead.
 */
#if !defined(ESP_PLATFORM)

#include "cz_port.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#if defined(_WIN32)
#include <bcrypt.h>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "bcrypt.lib")
#else
#include <netinet/tcp.h>
#include <sys/time.h>
#endif

struct cz_conn {
    int fd;
};

static void cz_host_startup(void)
{
#if defined(_WIN32)
    static bool started;
    if (!started) {
        WSADATA data;
        WSAStartup(MAKEWORD(2, 2), &data);
        started = true;
    }
#endif
}

cz_conn *cz_conn_open(const char *host, uint16_t port, bool tls, const char *root_ca_pem, int timeout_ms)
{
    (void)root_ca_pem;
    cz_host_startup();
    if (tls) {
        fprintf(stderr, "cz: this build has no TLS; use an http:// API address (a development platform on this machine)\n");
        return NULL;
    }
    int fd = cz_tcp_connect(host, port, timeout_ms);
    if (fd < 0) {
        return NULL;
    }
    cz_conn *conn = (cz_conn *)calloc(1, sizeof *conn);
    if (conn == NULL) {
        cz_socket_close(fd);
        return NULL;
    }
    conn->fd = fd;
    return conn;
}

int cz_conn_fd(const cz_conn *conn)
{
    return conn->fd;
}

bool cz_conn_pending(cz_conn *conn)
{
    (void)conn;
    return false;
}

int cz_conn_read(cz_conn *conn, uint8_t *out, int capacity)
{
    int read = (int)recv(conn->fd, (char *)out, capacity, 0);
    if (read > 0) {
        return read;
    }
    if (read == 0) {
        return -1;
    }
    return cz_socket_would_block() ? 0 : -1;
}

bool cz_conn_write(cz_conn *conn, const uint8_t *data, size_t size, int timeout_ms)
{
    uint32_t started = cz_millis();
    while (size > 0) {
        int sent = (int)send(conn->fd, (const char *)data, (int)size, 0);
        if (sent > 0) {
            data += sent;
            size -= (size_t)sent;
            continue;
        }
        if (!cz_socket_would_block() || (int)(cz_millis() - started) > timeout_ms) {
            return false;
        }
        fd_set writable;
        FD_ZERO(&writable);
        FD_SET(conn->fd, &writable);
        struct timeval wait = { 0, 50 * 1000 };
        select(conn->fd + 1, NULL, &writable, NULL, &wait);
    }
    return true;
}

void cz_conn_close(cz_conn *conn)
{
    if (conn != NULL) {
        cz_socket_close(conn->fd);
        free(conn);
    }
}

uint32_t cz_millis(void)
{
#if defined(_WIN32)
    return (uint32_t)GetTickCount64();
#else
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (uint32_t)((uint64_t)now.tv_sec * 1000u + (uint64_t)now.tv_nsec / 1000000u);
#endif
}

void cz_sleep_ms(int milliseconds)
{
#if defined(_WIN32)
    Sleep((DWORD)milliseconds);
#else
    struct timespec wait = { milliseconds / 1000, (long)(milliseconds % 1000) * 1000000L };
    nanosleep(&wait, NULL);
#endif
}

void cz_random(uint8_t *out, size_t size)
{
#if defined(_WIN32)
    if (BCryptGenRandom(NULL, out, (ULONG)size, BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) {
        abort(); /* never continue with keys that are not random */
    }
#else
    FILE *source = fopen("/dev/urandom", "rb");
    if (source == NULL || fread(out, 1, size, source) != size) {
        abort(); /* never continue with keys that are not random */
    }
    fclose(source);
#endif
}

const char *cz_platform_name(void)
{
#if defined(_WIN32)
    return "host-windows";
#elif defined(__APPLE__)
    return "host-macos";
#else
    return "host-linux";
#endif
}

uint32_t cz_local_address(void)
{
    /* Connecting a UDP socket sends nothing; it only makes the system choose the route, and with
       it the local address it would use. */
    int fd = (int)socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0) {
        return 0;
    }
    struct sockaddr_in remote;
    memset(&remote, 0, sizeof remote);
    remote.sin_family = AF_INET;
    remote.sin_port = htons(53);
    remote.sin_addr.s_addr = htonl(0x08080808u);
    uint32_t address = 0;
    struct sockaddr_in local;
    cz_socklen size = sizeof local;
    if (connect(fd, (struct sockaddr *)&remote, sizeof remote) == 0 && getsockname(fd, (struct sockaddr *)&local, &size) == 0) {
        address = local.sin_addr.s_addr;
    }
    cz_socket_close(fd);
    return address;
}

void cz_ipv6_enable(void)
{
    /* A PC configures IPv6 by itself. */
}

int cz_local_ipv6(uint8_t (*out)[16], int max)
{
    /* The same trick as for IPv4: the address the system would send from to a global IPv6
       address (Google's resolver; nothing is sent). One address is enough for the tests. */
    if (max < 1) {
        return 0;
    }
    int fd = (int)socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0) {
        return 0;
    }
    struct sockaddr_in6 remote;
    memset(&remote, 0, sizeof remote);
    remote.sin6_family = AF_INET6;
    remote.sin6_port = htons(53);
    static const uint8_t resolver[16] = { 0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0x88, 0x88 };
    memcpy(&remote.sin6_addr, resolver, 16);
    struct sockaddr_in6 local;
    cz_socklen size = sizeof local;
    int count = 0;
    if (connect(fd, (struct sockaddr *)&remote, sizeof remote) == 0 && getsockname(fd, (struct sockaddr *)&local, &size) == 0) {
        const uint8_t *bytes = (const uint8_t *)&local.sin6_addr;
        if ((bytes[0] & 0xE0) == 0x20) { /* global unicast, 2000::/3 */
            memcpy(out[0], bytes, 16);
            count = 1;
        }
    }
    cz_socket_close(fd);
    return count;
}

#endif
