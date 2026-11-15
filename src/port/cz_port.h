/*
 * What the library needs from the system it runs on: BSD sockets (which lwIP on the ESP32 and a
 * PC both have), a TLS connection for the links to the platform, time and randomness.
 * cz_port_esp.c implements it for ESP32 (ESP-IDF and Arduino), cz_port_host.c for Linux, macOS
 * and Windows, where the same code runs for the tests.
 */
#ifndef CZ_PORT_H
#define CZ_PORT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
typedef int cz_socklen;
#else
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>
typedef socklen_t cz_socklen;
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* A TCP connection, with TLS on top when asked for. */
typedef struct cz_conn cz_conn;

/* Connects (and completes the TLS handshake). NULL when the server could not be reached or verified. */
cz_conn *cz_conn_open(const char *host, uint16_t port, bool tls, const char *root_ca_pem, int timeout_ms);

/* The socket, for select(). */
int cz_conn_fd(const cz_conn *conn);

/* True when bytes can be read without the socket becoming readable first (TLS keeps decrypted data). */
bool cz_conn_pending(cz_conn *conn);

/* Reads without waiting. Returns the bytes read, 0 when there are none right now, -1 when the connection is closed. */
int cz_conn_read(cz_conn *conn, uint8_t *out, int capacity);

/* Writes everything, waiting at most timeout_ms for the peer to take it. */
bool cz_conn_write(cz_conn *conn, const uint8_t *data, size_t size, int timeout_ms);

void cz_conn_close(cz_conn *conn);

/* Milliseconds since some fixed moment; wraps around after 49 days. */
uint32_t cz_millis(void);

void cz_sleep_ms(int milliseconds);

/* Cryptographically secure random bytes. */
void cz_random(uint8_t *out, size_t size);

/* Plain sockets (local services, UDP): the calls that differ between systems. */
bool cz_socket_set_nonblocking(int fd);
void cz_socket_close(int fd);
bool cz_socket_would_block(void);

/* Opens a non-blocking TCP connection to host:port and waits at most timeout_ms. Returns the socket, or -1. */
int cz_tcp_connect(const char *host, uint16_t port, int timeout_ms);

/* The IPv4 address (network byte order) of `host`, which may be a name. False when it cannot be resolved. */
bool cz_resolve(const char *host, uint32_t *address);

/* The IPv4 address this machine uses to reach other networks (network byte order), or 0. */
uint32_t cz_local_address(void);

/*
 * IPv6 for the direct path. CZ_IPV6 is defined where the system has IPv6 sockets: always on a PC,
 * and on an ESP32 unless IPv6 was switched off in its lwIP configuration.
 */
#if !defined(ESP_PLATFORM)
#define CZ_IPV6 1
#else
#include "sdkconfig.h"
#if defined(CONFIG_LWIP_IPV6)
#define CZ_IPV6 1
#endif
#endif

/* Lets the network interface acquire IPv6 addresses (link-local, then global ones from the router). Safe to call repeatedly. */
void cz_ipv6_enable(void);

/* Up to `max` global IPv6 addresses of this machine (16 bytes each, as on the wire). Returns how many. */
int cz_local_ipv6(uint8_t (*out)[16], int max);

/* A short description of the hardware, shown in the web app next to the device. */
const char *cz_platform_name(void);

#ifdef __cplusplus
}
#endif

#endif
