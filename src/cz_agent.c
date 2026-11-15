/*
 * The device: one loop that keeps the connection to the platform, answers connection offers and
 * serves sessions. Everything runs on one task and nothing blocks except connecting.
 *
 * Memory: an idle agent holds two buffers of 4 KB. Each session adds about 10 KB while it lasts,
 * plus its path (a TLS connection to the relay, or the KCP windows of a direct path).
 */
#include "cz_internal.h"

#include "vendor/ikcp.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

/* ---- Sizes and timings -------------------------------------------------------------------- */

#define BUFFER_SIZE 4096
#define MUX_HEADER 12
#define TX_OFFSET (CZ_WS_HEADROOM + 2)        /* room for a WebSocket header and the message length */
#define MAX_DATA (CZ_MAX_PLAINTEXT - MUX_HEADER) /* one mux frame travels in one encrypted message */
#define INITIAL_WINDOW 262144u
#define CONTROL_SIZE 2048
#define DATAGRAM_SIZE 1200
/* KCP windows in segments of about 1.2 KB: what a direct path may hold in memory in each direction. */
#ifndef CZ_KCP_WINDOW
#if defined(ESP_PLATFORM)
#define CZ_KCP_WINDOW 16
#else
#define CZ_KCP_WINDOW 64
#endif
#endif
#define MAX_CANDIDATES 16
#define MAX_IPV6_ADDRESSES 3 /* lwIP keeps three per interface */
#define MAX_LEARNED 4

#define PING_INTERVAL_MS 25000
#define SILENCE_LIMIT_MS 70000
#define HELLO_TIMEOUT_MS 15000
#define PAIR_TIMEOUT_MS 20000
#define DIRECT_TIMEOUT_MS 12000
#define HANDSHAKE_TIMEOUT_MS 15000
#define STUN_TIMEOUT_MS 1500
#define PROBE_INTERVAL_MS 100
#define KEEP_ALIVE_MS 15000
#define IDLE_TIMEOUT_MS 45000
#define LEASE_GRACE_SECONDS 30
#define KEY_REFRESH_MS 30000

enum { MUX_DATA = 0, MUX_WINDOW_UPDATE = 1, MUX_PING = 2, MUX_GO_AWAY = 3 };
enum { FLAG_SYN = 1, FLAG_ACK = 2, FLAG_FIN = 4, FLAG_RST = 8 };
enum { DGRAM_PROBE = 0xC1, DGRAM_PROBE_ACK = 0xC2, DGRAM_KCP = 0xC3, DGRAM_KEEP_ALIVE = 0xC4, DGRAM_CLOSE = 0xC5 };

typedef enum {
    PHASE_GATHER,    /* direct: asking the STUN servers */
    PHASE_PUNCH,     /* direct: probing, waiting for the initiator to select a path or to fall back */
    PHASE_PAIRING,   /* relay: waiting for the initiator to arrive */
    PHASE_HANDSHAKE, /* waiting for the initiator's handshake message */
    PHASE_BIND,      /* encrypted; waiting for the session bind */
    PHASE_OPEN       /* established */
} cz_phase;

typedef struct {
    bool used;
    bool open;        /* the service was opened and the stream carries its bytes */
    bool refused;     /* the service was refused; what else arrives is dropped */
    bool acknowledged;
    bool local_done;  /* this side finished sending */
    bool remote_done; /* the peer finished sending */
    uint32_t id;
    int fd;
    uint32_t send_window;
    uint32_t consumed;
    uint8_t preamble[2 + 96];
    int preamble_used;
} cz_stream;

typedef struct {
    bool ipv6;        /* which of the two addresses holds */
    uint32_t address; /* IPv4, network byte order */
    uint8_t v6[16];   /* IPv6, as on the wire */
    uint16_t port;    /* host byte order */
} cz_endpoint;

typedef struct {
    int fd;
    bool ipv6; /* the socket is dual-stack: it reaches IPv4 and IPv6 peers */
    uint16_t port;
    uint8_t tag[8];
    uint32_t conversation;
    cz_endpoint remote[MAX_CANDIDATES];
    int remote_count;
    bool remote_known;
    /* Addresses of the initiator it did not announce, learned from where its probes came from. */
    cz_endpoint learned[MAX_LEARNED];
    int learned_count;
    char local_hash[65];
    char remote_hash[65];
    struct {
        cz_endpoint server;
        uint8_t id[12];
        bool answered;
        cz_endpoint mapped;
    } stun[2];
    int stun_count;
    uint32_t started;
    uint32_t last_request;
    int requests;
    uint32_t last_probe;
    bool selected;
    cz_endpoint peer;
    ikcpcb *kcp;
    uint32_t last_received;
    uint32_t last_sent;
    uint8_t in[DATAGRAM_SIZE];
    int in_used;
    int in_offset;
    bool peer_closed;
    /* For the log line when no direct path was found: what arrived, and from where. */
    int probes_received;
    cz_endpoint unannounced;
} cz_direct;

typedef struct cz_session {
    cz_agent *agent;
    cz_phase phase;
    cz_grant grant;
    char *token;
    char grant_hash[65];
    char peer_name[CZ_NAME_SIZE];
    bool peer_direct; /* the initiator can do UDP */
    bool direct;      /* the session runs (or tries to run) on a direct path */
    bool established;
    uint32_t phase_started;
    int64_t lease_expires;
    cz_ws relay;
    cz_direct *d;
    cz_noise_transport noise;
    /* One encrypted message at a time: collected here, decrypted in place, consumed from here. */
    uint8_t rx[2 + CZ_MAX_PLAINTEXT + CZ_TAG_SIZE];
    int rx_used;
    int plain_at;
    int plain_end;
    uint8_t tx[TX_OFFSET + CZ_MAX_PLAINTEXT + CZ_TAG_SIZE];
    /* Mux parsing */
    uint8_t mux_header[MUX_HEADER];
    int mux_header_used;
    uint32_t frame_left;
    cz_stream *frame_stream;
    uint16_t frame_flags;
    bool in_frame;
    uint32_t last_remote_stream;
    cz_stream control;
    bool bound;
    uint8_t control_buffer[CONTROL_SIZE];
    int control_used;
    cz_stream streams[CZ_MAX_STREAMS];
    int blocked_fd; /* a local service that cannot take more right now, or -1 */
    uint64_t bytes_sent;
    uint64_t bytes_received;
    bool ended;
} cz_session;

typedef struct {
    char name[CZ_NAME_SIZE];
    char host[64];
    uint16_t port;
    char protocol[8];
} cz_service_entry;

struct cz_agent {
    cz_url api;
    char device_key[96];
    char name[CZ_NAME_SIZE];
    uint8_t keys[CZ_MAX_SHARED_KEYS][CZ_KEY_SIZE];
    int key_count;
    cz_service_entry services[CZ_MAX_SERVICES];
    int service_count;
    bool peer_to_peer;
    bool include_loopback;
    char *root_ca;
    char platform[48];
    cz_log_fn log;
    void *log_user;

    cz_state state;
    volatile bool stop;
    char last_error[40];
    char device_id[CZ_ID_SIZE];
    int64_t clock_offset; /* platform time minus local uptime, in seconds */

    cz_ws signal;
    bool signal_open;
    bool welcomed;
    uint32_t connected_at;
    uint32_t last_received;
    uint32_t last_ping;
    uint32_t next_attempt;
    uint32_t backoff;
    uint32_t message_id;
    char stun[2][64];
    int stun_count;

    cz_grant_key grant_keys[CZ_MAX_GRANT_KEYS];
    int grant_key_count;
    uint32_t keys_fetched_at;
    bool keys_fetched;

    char message[BUFFER_SIZE]; /* the signaling message being received, or an HTTP response */
    int message_used;
    bool message_overflow;
    char scratch[BUFFER_SIZE]; /* whatever is being built or decoded right now */

    cz_session *sessions[CZ_MAX_SESSIONS];
};

/* ---- Small helpers ------------------------------------------------------------------------ */

static void agent_log(cz_agent *agent, const char *format, ...)
{
    if (agent->log == NULL) {
        return;
    }
    char line[320];
    va_list arguments;
    va_start(arguments, format);
    vsnprintf(line, sizeof line, format, arguments);
    va_end(arguments);
    agent->log(line, agent->log_user);
}

static int64_t agent_now(const cz_agent *agent)
{
    return agent->clock_offset + (int64_t)(cz_millis() / 1000u);
}

static bool elapsed(uint32_t since, uint32_t milliseconds)
{
    return (uint32_t)(cz_millis() - since) >= milliseconds;
}

static void put32(uint8_t *out, uint32_t value)
{
    out[0] = (uint8_t)(value >> 24);
    out[1] = (uint8_t)(value >> 16);
    out[2] = (uint8_t)(value >> 8);
    out[3] = (uint8_t)value;
}

static uint32_t get32(const uint8_t *in)
{
    return ((uint32_t)in[0] << 24) | ((uint32_t)in[1] << 16) | ((uint32_t)in[2] << 8) | in[3];
}

static bool text_member(cz_span object, const char *member, char *out, size_t capacity)
{
    cz_span value;
    return cz_json_member(object, member, &value) && cz_json_string(value, out, capacity);
}

static cz_endpoint endpoint_v4(uint32_t address, uint16_t port)
{
    cz_endpoint endpoint;
    memset(&endpoint, 0, sizeof endpoint);
    endpoint.address = address;
    endpoint.port = port;
    return endpoint;
}

static bool endpoint_set(cz_endpoint endpoint)
{
    return endpoint.port != 0;
}

/* An IPv4-mapped IPv6 address (::ffff:a.b.c.d), which a dual-stack socket reports for an IPv4 peer. */
static bool v6_is_mapped(const uint8_t *v6)
{
    static const uint8_t prefix[12] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF };
    return memcmp(v6, prefix, 12) == 0;
}

/* `a.b.c.d:port`, or `[address]:port` for IPv6 (protocol section 6.3). */
static void format_endpoint(cz_endpoint endpoint, char *out, size_t capacity)
{
#if defined(CZ_IPV6)
    if (endpoint.ipv6) {
        char text[48];
        if (inet_ntop(AF_INET6, endpoint.v6, text, sizeof text) == NULL) {
            cz_copy(text, sizeof text, "::");
        }
        snprintf(out, capacity, "[%s]:%u", text, (unsigned)endpoint.port);
        return;
    }
#endif
    const uint8_t *a = (const uint8_t *)&endpoint.address;
    snprintf(out, capacity, "%u.%u.%u.%u:%u", a[0], a[1], a[2], a[3], (unsigned)endpoint.port);
}

static bool parse_endpoint(const char *text, cz_endpoint *out)
{
    memset(out, 0, sizeof *out);
    if (text[0] == '[') {
#if defined(CZ_IPV6)
        const char *close = strstr(text, "]:");
        char host[48];
        char *end;
        if (close == NULL || (size_t)(close - text - 1) >= sizeof host) {
            return false;
        }
        memcpy(host, text + 1, (size_t)(close - text - 1));
        host[close - text - 1] = '\0';
        long port = strtol(close + 2, &end, 10);
        if (*end != '\0' || port < 1 || port > 65535 || inet_pton(AF_INET6, host, out->v6) != 1) {
            return false;
        }
        out->port = (uint16_t)port;
        if (v6_is_mapped(out->v6)) {
            memcpy(&out->address, out->v6 + 12, 4);
            memset(out->v6, 0, sizeof out->v6);
            return true;
        }
        /* Link-local addresses would need an interface to go with them; multicast is never a peer. */
        bool link_local = out->v6[0] == 0xFE && (out->v6[1] & 0xC0) == 0x80;
        out->ipv6 = true;
        return !link_local && out->v6[0] != 0xFF;
#else
        return false;
#endif
    }
    unsigned a, b, c, d, port;
    char rest;
    if (sscanf(text, "%3u.%3u.%3u.%3u:%5u%c", &a, &b, &c, &d, &port, &rest) != 5 || a > 255 || b > 255 || c > 255 || d > 255 || port < 1 || port > 65535) {
        return false;
    }
    uint8_t *bytes = (uint8_t *)&out->address;
    bytes[0] = (uint8_t)a;
    bytes[1] = (uint8_t)b;
    bytes[2] = (uint8_t)c;
    bytes[3] = (uint8_t)d;
    out->port = (uint16_t)port;
    return true;
}

static bool same_endpoint(cz_endpoint a, cz_endpoint b)
{
    if (a.ipv6 != b.ipv6 || a.port != b.port) {
        return false;
    }
    return a.ipv6 ? memcmp(a.v6, b.v6, 16) == 0 : a.address == b.address;
}

/* ---- Signaling: sending ------------------------------------------------------------------- */

/* Sends the JSON text that was written to agent->scratch + CZ_WS_HEADROOM. */
static bool signal_send(cz_agent *agent, int length)
{
    if (!agent->signal_open || length <= 0 || length >= BUFFER_SIZE - CZ_WS_HEADROOM) {
        return false;
    }
    return cz_ws_send(&agent->signal, true, (uint8_t *)agent->scratch + CZ_WS_HEADROOM, (size_t)length);
}

static char *signal_buffer(cz_agent *agent, size_t *capacity)
{
    *capacity = BUFFER_SIZE - CZ_WS_HEADROOM;
    return agent->scratch + CZ_WS_HEADROOM;
}

static void report_session(cz_session *session, const char *state, const char *error)
{
    cz_agent *agent = session->agent;
    size_t capacity;
    char *json = signal_buffer(agent, &capacity);
    int length;
    if (strcmp(state, "established") == 0) {
        length = snprintf(json, capacity, "{\"t\":\"session.update\",\"d\":{\"sid\":\"%s\",\"state\":\"established\",\"mode\":\"%s\",\"trust\":\"shared-key\",\"transport\":\"%s\"}}",
                          session->grant.session_id, session->direct ? "direct" : "e2e-relay", session->direct ? "udp-kcp" : "relay-ws");
    } else {
        length = snprintf(json, capacity, "{\"t\":\"session.update\",\"d\":{\"sid\":\"%s\",\"state\":\"%s\",\"error\":\"%s\",\"bytesSent\":%llu,\"bytesReceived\":%llu}}",
                          session->grant.session_id, state, error, (unsigned long long)session->bytes_sent, (unsigned long long)session->bytes_received);
    }
    signal_send(agent, length);
}

/* ---- Direct path: datagrams, STUN, KCP (protocol section 6) -------------------------------- */

static void udp_send(cz_direct *d, const uint8_t *data, size_t size, cz_endpoint to)
{
#if defined(CZ_IPV6)
    if (d->ipv6) {
        /* A dual-stack socket reaches an IPv4 peer by its IPv4-mapped address. */
        struct sockaddr_in6 address;
        memset(&address, 0, sizeof address);
        address.sin6_family = AF_INET6;
        address.sin6_port = htons(to.port);
        uint8_t *bytes = (uint8_t *)&address.sin6_addr;
        if (to.ipv6) {
            memcpy(bytes, to.v6, 16);
        } else {
            bytes[10] = 0xFF;
            bytes[11] = 0xFF;
            memcpy(bytes + 12, &to.address, 4);
        }
        sendto(d->fd, (const char *)data, (int)size, 0, (struct sockaddr *)&address, sizeof address);
        return;
    }
#endif
    if (to.ipv6) {
        return; /* an IPv6 candidate this socket cannot reach */
    }
    struct sockaddr_in address;
    memset(&address, 0, sizeof address);
    address.sin_family = AF_INET;
    address.sin_port = htons(to.port);
    address.sin_addr.s_addr = to.address;
    sendto(d->fd, (const char *)data, (int)size, 0, (struct sockaddr *)&address, sizeof address);
}

/* The sender of a received datagram; an IPv4-mapped address as the IPv4 address it stands for. */
static cz_endpoint endpoint_from(const struct sockaddr_storage *from)
{
    cz_endpoint endpoint;
    memset(&endpoint, 0, sizeof endpoint);
#if defined(CZ_IPV6)
    if (from->ss_family == AF_INET6) {
        const struct sockaddr_in6 *address = (const struct sockaddr_in6 *)from;
        const uint8_t *bytes = (const uint8_t *)&address->sin6_addr;
        endpoint.port = ntohs(address->sin6_port);
        if (v6_is_mapped(bytes)) {
            memcpy(&endpoint.address, bytes + 12, 4);
        } else {
            endpoint.ipv6 = true;
            memcpy(endpoint.v6, bytes, 16);
        }
        return endpoint;
    }
#endif
    const struct sockaddr_in *address = (const struct sockaddr_in *)from;
    endpoint.address = address->sin_addr.s_addr;
    endpoint.port = ntohs(address->sin_port);
    return endpoint;
}

/* A UDP socket on a free port: dual-stack where there is IPv6, IPv4 only otherwise. -1 on failure. */
static int udp_open(bool *ipv6, uint16_t *port)
{
#if defined(CZ_IPV6)
    int fd = (int)socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    if (fd >= 0) {
        int off = 0; /* not IPv6 only: IPv4 peers arrive as IPv4-mapped addresses */
        struct sockaddr_in6 local;
        cz_socklen local_size = sizeof local;
        memset(&local, 0, sizeof local);
        local.sin6_family = AF_INET6;
        if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, (const char *)&off, sizeof off) == 0
            && bind(fd, (struct sockaddr *)&local, sizeof local) == 0
            && getsockname(fd, (struct sockaddr *)&local, &local_size) == 0) {
            *ipv6 = true;
            *port = ntohs(local.sin6_port);
            return fd;
        }
        cz_socket_close(fd);
    }
#endif
    int fd4 = (int)socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    struct sockaddr_in local4;
    cz_socklen local4_size = sizeof local4;
    memset(&local4, 0, sizeof local4);
    local4.sin_family = AF_INET;
    if (fd4 < 0 || bind(fd4, (struct sockaddr *)&local4, sizeof local4) != 0 || getsockname(fd4, (struct sockaddr *)&local4, &local4_size) != 0) {
        cz_socket_close(fd4);
        return -1;
    }
    *ipv6 = false;
    *port = ntohs(local4.sin_port);
    return fd4;
}

static int kcp_output(const char *buffer, int length, ikcpcb *kcp, void *user)
{
    cz_direct *d = (cz_direct *)user;
    uint8_t datagram[DATAGRAM_SIZE];
    (void)kcp;
    if (length <= 0 || length > DATAGRAM_SIZE - 1) {
        return -1;
    }
    /* One byte in front of every KCP packet says what the datagram is. */
    datagram[0] = DGRAM_KCP;
    memcpy(datagram + 1, buffer, (size_t)length);
    d->last_sent = cz_millis();
    udp_send(d, datagram, (size_t)length + 1, d->peer);
    return 0;
}

static void direct_close(cz_direct *d, bool announce)
{
    if (d == NULL) {
        return;
    }
    if (d->kcp != NULL) {
        if (announce) {
            /* Give what was written a chance to leave, then tell the peer this side is done. */
            ikcp_flush(d->kcp);
            uint8_t close = DGRAM_CLOSE;
            udp_send(d, &close, 1, d->peer);
            udp_send(d, &close, 1, d->peer);
        }
        ikcp_release(d->kcp);
    }
    cz_socket_close(d->fd);
    free(d);
}

static void stun_send_requests(cz_direct *d)
{
    for (int i = 0; i < d->stun_count; i++) {
        if (!d->stun[i].answered) {
            uint8_t request[20];
            request[0] = 0x00;
            request[1] = 0x01; /* Binding request */
            request[2] = 0;
            request[3] = 0;
            put32(request + 4, 0x2112A442u);
            memcpy(request + 8, d->stun[i].id, 12);
            udp_send(d, request, sizeof request, d->stun[i].server);
        }
    }
    d->last_request = cz_millis();
    d->requests++;
}

/* Reads the mapped address from a STUN Binding success response for one of the transactions. */
static void stun_input(cz_direct *d, const uint8_t *data, int size)
{
    if (size < 20 || data[0] != 0x01 || data[1] != 0x01 || get32(data + 4) != 0x2112A442u) {
        return;
    }
    int length = (data[2] << 8) | data[3];
    if (length > size - 20) {
        return;
    }
    for (int i = 0; i < d->stun_count; i++) {
        if (d->stun[i].answered || memcmp(data + 8, d->stun[i].id, 12) != 0) {
            continue;
        }
        int offset = 20;
        int end = 20 + length;
        while (end - offset >= 4) {
            int type = (data[offset] << 8) | data[offset + 1];
            int value_length = (data[offset + 2] << 8) | data[offset + 3];
            if (value_length > end - offset - 4) {
                return;
            }
            if (type == 0x0020 && value_length >= 8 && data[offset + 5] == 0x01) {
                uint32_t address = get32(data + offset + 8) ^ 0x2112A442u;
                uint8_t *bytes = (uint8_t *)&d->stun[i].mapped.address;
                put32(bytes, address);
                d->stun[i].mapped.port = (uint16_t)(((data[offset + 6] << 8) | data[offset + 7]) ^ 0x2112);
                d->stun[i].answered = true;
                return;
            }
            offset += 4 + ((value_length + 3) & ~3); /* attributes are padded to four bytes */
        }
    }
}

static bool direct_is_candidate(const cz_direct *d, cz_endpoint from)
{
    for (int i = 0; i < d->remote_count; i++) {
        if (same_endpoint(d->remote[i], from)) {
            return true;
        }
    }
    return false;
}

static bool direct_is_learned(const cz_direct *d, cz_endpoint from)
{
    for (int i = 0; i < d->learned_count; i++) {
        if (same_endpoint(d->learned[i], from)) {
            return true;
        }
    }
    return false;
}

/*
 * Remembers an address of the initiator it did not announce, because a probe with this session's
 * tag came from it (behind a symmetric NAT the initiator's packets come from a port it cannot
 * know in advance). Only once the initiator's list is known, so that it is clear the address is not
 * on it. Allowed because every session of this library runs the shared-key handshake, which
 * authenticates the peer on whatever path is selected (protocol section 6.5).
 */
static void direct_learn(cz_direct *d, cz_endpoint from)
{
    if (!d->remote_known || d->learned_count >= MAX_LEARNED || direct_is_candidate(d, from) || direct_is_learned(d, from)) {
        return;
    }
    d->learned[d->learned_count++] = from;
}

static void session_set_phase(cz_session *session, cz_phase phase)
{
    session->phase = phase;
    session->phase_started = cz_millis();
}

/* A probe carries no payload and proves nothing: it only finds a path that works. */
static void direct_probe_input(cz_session *session, const uint8_t *data, int size, cz_endpoint from)
{
    cz_direct *d = session->d;
    if (size != 18 || !cz_equal(data + 1, d->tag, 8) || data[0] != DGRAM_PROBE) {
        return; /* not for this session, or an acknowledgement, which only the initiator uses */
    }
    d->probes_received++;
    if (!direct_is_candidate(d, from)) {
        d->unannounced = from;
        direct_learn(d, from);
    }
    if (data[9] == 1) {
        /* A "select": accepted from an address the initiator announced, or one learned from its probes. */
        if (!direct_is_candidate(d, from) && !direct_is_learned(d, from)) {
            return;
        }
        if (!d->selected) {
            d->kcp = ikcp_create(d->conversation, d);
            if (d->kcp == NULL) {
                return;
            }
            ikcp_setoutput(d->kcp, kcp_output);
            d->kcp->stream = 1;
            ikcp_setmtu(d->kcp, DATAGRAM_SIZE - 1);
            ikcp_nodelay(d->kcp, 1, 10, 2, 1);
            ikcp_wndsize(d->kcp, CZ_KCP_WINDOW, 128);
            /* A smaller receive window than the reference allows by its setter: fine in stream mode,
               and what bounds the memory of this side. The peer never sends more than it is told. */
            d->kcp->rcv_wnd = CZ_KCP_WINDOW;
            d->selected = true;
            d->peer = from;
            d->last_received = d->last_sent = cz_millis();
            /* The path listens before the selection is acknowledged, so the initiator's first packets are not lost. */
            session_set_phase(session, PHASE_HANDSHAKE);
        } else if (!same_endpoint(d->peer, from)) {
            return;
        }
    }
    uint8_t ack[18];
    memcpy(ack, data, sizeof ack);
    ack[0] = DGRAM_PROBE_ACK;
    udp_send(d, ack, sizeof ack, from);
}

static void direct_input(cz_session *session)
{
    cz_direct *d = session->d;
    uint8_t datagram[DATAGRAM_SIZE + 64];
    for (int i = 0; i < 32; i++) {
        struct sockaddr_storage address;
        cz_socklen address_size = sizeof address;
        int size = (int)recvfrom(d->fd, (char *)datagram, (int)sizeof datagram, 0, (struct sockaddr *)&address, &address_size);
        if (size <= 0) {
            return;
        }
        cz_endpoint from = endpoint_from(&address);
        if (datagram[0] <= 0x03) {
            stun_input(d, datagram, size);
        } else if (datagram[0] == DGRAM_PROBE || datagram[0] == DGRAM_PROBE_ACK) {
            direct_probe_input(session, datagram, size, from);
        } else if (d->selected && same_endpoint(d->peer, from)) {
            d->last_received = cz_millis();
            if (datagram[0] == DGRAM_KCP && size > 1) {
                ikcp_input(d->kcp, (const char *)datagram + 1, size - 1);
            } else if (datagram[0] == DGRAM_CLOSE) {
                d->peer_closed = true;
            }
        }
    }
}

/* ---- Session: sending --------------------------------------------------------------------- */

static void session_end(cz_session *session, const char *reason, bool tell_peer);

/* Encrypts the `size` plaintext bytes at session->tx + TX_OFFSET and sends them as one message. */
static bool session_send(cz_session *session, size_t size)
{
    uint8_t *plain = session->tx + TX_OFFSET;
    cz_noise_encrypt(&session->noise, plain, size);
    size_t message = size + CZ_TAG_SIZE;
    plain[-2] = (uint8_t)(message >> 8);
    plain[-1] = (uint8_t)message;
    if (session->direct) {
        return ikcp_send(session->d->kcp, (const char *)plain - 2, (int)message + 2) >= 0;
    }
    return cz_ws_send(&session->relay, false, plain - 2, message + 2);
}

/* Sends a mux frame; a payload of `payload_size` bytes must already be at tx + TX_OFFSET + MUX_HEADER. */
static bool session_send_frame(cz_session *session, int type, int flags, uint32_t stream, uint32_t length, size_t payload_size)
{
    uint8_t *header = session->tx + TX_OFFSET;
    header[0] = 0;
    header[1] = (uint8_t)type;
    header[2] = (uint8_t)(flags >> 8);
    header[3] = (uint8_t)flags;
    put32(header + 4, stream);
    put32(header + 8, length);
    if (!session_send(session, MUX_HEADER + payload_size)) {
        session_end(session, "PATH_CLOSED", false);
        return false;
    }
    return true;
}

/* The accepting side marks the first frame it sends for a stream. */
static int first_frame_flags(cz_stream *stream)
{
    if (stream->acknowledged) {
        return 0;
    }
    stream->acknowledged = true;
    return FLAG_ACK;
}

/* Sends `size` bytes that were written to session_payload() as data on a stream. */
static uint8_t *session_payload(cz_session *session)
{
    return session->tx + TX_OFFSET + MUX_HEADER;
}

static bool stream_send(cz_session *session, cz_stream *stream, size_t size)
{
    /* Everything sent on a stream counts against the peer's window - the few bytes of an answer as much as service data. */
    stream->send_window = stream->send_window > size ? stream->send_window - (uint32_t)size : 0;
    return session_send_frame(session, MUX_DATA, first_frame_flags(stream), stream->id, (uint32_t)size, size);
}

/* A JSON message with a length prefix of 2 (service streams) or 4 (control stream) bytes. */
static bool stream_send_json(cz_session *session, cz_stream *stream, int prefix, const char *json)
{
    uint8_t *payload = session_payload(session);
    size_t length = strlen(json);
    if (prefix == 2) {
        payload[0] = (uint8_t)(length >> 8);
        payload[1] = (uint8_t)length;
    } else {
        put32(payload, (uint32_t)length);
    }
    memcpy(payload + prefix, json, length);
    return stream_send(session, stream, (size_t)prefix + length);
}

static void stream_release(cz_session *session, cz_stream *stream)
{
    if (stream->fd >= 0) {
        if (session->blocked_fd == stream->fd) {
            session->blocked_fd = -1;
        }
        cz_socket_close(stream->fd);
    }
    if (session->frame_stream == stream) {
        session->frame_stream = NULL; /* the rest of the frame being received is dropped */
    }
    memset(stream, 0, sizeof *stream);
    stream->fd = -1;
}

static void stream_reset(cz_session *session, cz_stream *stream)
{
    uint32_t id = stream->id;
    stream_release(session, stream);
    session_send_frame(session, MUX_WINDOW_UPDATE, FLAG_RST, id, 0, 0);
}

/* ---- Session: end ------------------------------------------------------------------------- */

static void session_close_path(cz_session *session, bool announce)
{
    if (session->d != NULL) {
        direct_close(session->d, announce && session->d->selected);
        session->d = NULL;
    }
    cz_ws_close(&session->relay, 1000);
}

static void session_free(cz_session *session)
{
    cz_agent *agent = session->agent;
    for (int i = 0; i < CZ_MAX_STREAMS; i++) {
        if (session->streams[i].used && session->streams[i].fd >= 0) {
            cz_socket_close(session->streams[i].fd);
        }
    }
    for (int i = 0; i < CZ_MAX_SESSIONS; i++) {
        if (agent->sessions[i] == session) {
            agent->sessions[i] = NULL;
        }
    }
    memset(&session->noise, 0, sizeof session->noise);
    free(session->token);
    free(session);
}

/*
 * Ends a session for `reason` (an error code). The session's memory is released by the main loop,
 * because this may be called from deep inside the code that is working on the session.
 */
static void session_end(cz_session *session, const char *reason, bool tell_peer)
{
    cz_agent *agent = session->agent;
    if (session->ended) {
        return;
    }
    session->ended = true;
    if (tell_peer && session->phase >= PHASE_BIND && session->control.used) {
        /* The peer learns why, then the stream multiplexer says goodbye. */
        char json[64];
        snprintf(json, sizeof json, "{\"error\":\"%s\"}", reason);
        stream_send_json(session, &session->control, 4, json);
        uint8_t *header = session->tx + TX_OFFSET;
        memset(header, 0, MUX_HEADER);
        header[1] = MUX_GO_AWAY;
        session_send(session, MUX_HEADER);
    }
    session_close_path(session, true);
    agent_log(agent, "session %s with %s %s (%s)", session->grant.session_id, session->peer_name, session->established ? "ended" : "failed", reason);
    report_session(session, session->established ? "ended" : "failed", reason);
    cz_copy(agent->last_error, sizeof agent->last_error, strcmp(reason, "SESSION_CLOSED") == 0 ? "" : reason);
}

/* ---- Session: local services -------------------------------------------------------------- */

/* The device's own, local answer to "may this session use this service, and where does it go?". */
static void service_open(cz_session *session, cz_stream *stream, const char *name)
{
    cz_agent *agent = session->agent;
    const char *refusal = NULL;
    const cz_service_entry *service = NULL;
    bool granted = false;
    for (int i = 0; i < session->grant.service_count; i++) {
        granted = granted || strcmp(session->grant.services[i], name) == 0;
    }
    for (int i = 0; i < agent->service_count; i++) {
        if (strcmp(agent->services[i].name, name) == 0) {
            service = &agent->services[i];
        }
    }
    /* Platform authorisation (the grant) and the device's own configuration both have to agree. */
    if (!granted) {
        refusal = "DENIED_BY_GRANT";
    } else if (service == NULL) {
        refusal = "SERVICE_NOT_EXPOSED";
    } else {
        stream->fd = cz_tcp_connect(service->host, service->port, 3000);
        if (stream->fd < 0) {
            refusal = "TARGET_UNREACHABLE";
        }
    }

    if (refusal == NULL) {
        stream->open = true;
        stream_send_json(session, stream, 2, "{\"ok\":true}");
        return;
    }
    char json[64];
    snprintf(json, sizeof json, "{\"ok\":false,\"error\":\"%s\"}", refusal);
    agent_log(agent, "session %s: service '%s' refused (%s)", session->grant.session_id, name, refusal);
    stream->refused = true;
    stream->local_done = true;
    if (stream_send_json(session, stream, 2, json)) {
        session_send_frame(session, MUX_WINDOW_UPDATE, FLAG_FIN, stream->id, 0, 0);
    }
}

/* Tells the peer that it may send more on a stream, once enough of the window was used up. */
static void stream_consumed(cz_session *session, cz_stream *stream, uint32_t count)
{
    stream->consumed += count;
    if (stream->consumed >= INITIAL_WINDOW / 2 && !stream->remote_done) {
        uint32_t grant = stream->consumed;
        stream->consumed = 0;
        session_send_frame(session, MUX_WINDOW_UPDATE, first_frame_flags(stream), stream->id, grant, 0);
    }
}

/* ---- Session: control stream (bind, lease, error) ------------------------------------------ */

static void control_message(cz_session *session, cz_span message)
{
    cz_agent *agent = session->agent;
    cz_span value;
    char text[80];

    if (cz_json_member(message, "error", &value) && cz_json_string(value, text, sizeof text)) {
        session_end(session, text, false);
        return;
    }

    if (cz_json_member(message, "bind", &value)) {
        cz_span bind = value;
        char hash[65] = "";
        char role[16] = "";
        char mode[16] = "";
        char candidates[65] = "";
        text[0] = '\0';
        text_member(bind, "sid", text, sizeof text);
        text_member(bind, "grant", hash, sizeof hash);
        text_member(bind, "role", role, sizeof role);
        text_member(bind, "mode", mode, sizeof mode);
        text_member(bind, "cands", candidates, sizeof candidates);
        /* Both ends must agree on the session, the grant and the route each of them observed itself. */
        bool agrees = strcmp(text, session->grant.session_id) == 0 && strcmp(hash, session->grant_hash) == 0 && strcmp(role, "initiator") == 0
            && strcmp(mode, session->direct ? "direct" : "e2e-relay") == 0
            /* The addresses probed came through the control plane; here the authenticated peer confirms them. */
            && (!session->direct || (candidates[0] != '\0' && strcmp(candidates, session->d->remote_hash) == 0));
        if (!agrees || session->bound) {
            session_end(session, "E2E_SESSION_BIND_MISMATCH", true);
            return;
        }
        session->bound = true;
        session->established = true;
        session_set_phase(session, PHASE_OPEN);
        if (session->direct && session->d != NULL) {
            /* Where the app is: an address it announced, or one learned from its probes (protocol 6.5). */
            char peer[64];
            format_endpoint(session->d->peer, peer, sizeof peer);
            agent_log(agent, "session %s established with %s (direct, shared-key, app at %s, %s)", session->grant.session_id, session->peer_name, peer,
                      direct_is_candidate(session->d, session->d->peer) ? "announced" : "learned");
        } else {
            agent_log(agent, "session %s established with %s (e2e-relay, shared-key)", session->grant.session_id, session->peer_name);
        }
        report_session(session, "established", "");
        return;
    }

    if (session->bound && cz_json_member(message, "lease", &value)) {
        /* The token is copied out first: verifying needs the scratch buffer it would otherwise share. */
        cz_span token_value;
        char *token = (char *)malloc(CONTROL_SIZE);
        cz_grant renewed;
        if (token != NULL && cz_json_member(value, "grant", &token_value) && cz_json_string(token_value, token, CONTROL_SIZE)
            && cz_grant_verify(token, agent->grant_keys, agent->grant_key_count, agent_now(agent), false, (uint8_t *)agent->scratch, BUFFER_SIZE, &renewed) == NULL
            /* A renewal may only prolong this very session for the same two endpoints; it cannot widen anything. */
            && strcmp(renewed.session_id, session->grant.session_id) == 0 && strcmp(renewed.workspace_id, session->grant.workspace_id) == 0
            && strcmp(renewed.initiator_id, session->grant.initiator_id) == 0 && strcmp(renewed.device_id, session->grant.device_id) == 0
            && renewed.shared_key == session->grant.shared_key) {
            int64_t expires = renewed.issued_at + renewed.lease_seconds;
            if (expires > session->lease_expires) {
                session->lease_expires = expires;
            }
        }
        free(token);
    }
}

/* Returns how many of the `size` bytes were taken; the session may have ended. */
static int control_input(cz_session *session, const uint8_t *data, int size)
{
    for (int i = 0; i < size && !session->ended; i++) {
        if (session->control_used >= CONTROL_SIZE) {
            session_end(session, "MUX_PROTOCOL_ERROR", false);
            break;
        }
        session->control_buffer[session->control_used++] = data[i];
        if (session->control_used >= 4) {
            uint32_t length = get32(session->control_buffer);
            if (length == 0 || length > CONTROL_SIZE - 4) {
                session_end(session, "MUX_PROTOCOL_ERROR", false);
                break;
            }
            if ((uint32_t)session->control_used == 4 + length) {
                cz_span message = { (const char *)session->control_buffer + 4, length };
                session->control_used = 0;
                control_message(session, message);
            }
        }
    }
    return size;
}

/* ---- Session: stream multiplexer (protocol section 5) -------------------------------------- */

static cz_stream *session_find_stream(cz_session *session, uint32_t id)
{
    if (session->control.used && session->control.id == id) {
        return &session->control;
    }
    for (int i = 0; i < CZ_MAX_STREAMS; i++) {
        if (session->streams[i].used && session->streams[i].id == id) {
            return &session->streams[i];
        }
    }
    return NULL;
}

/* Data for a service stream. Returns how many bytes were taken; fewer than `size` means "come back later". */
static int stream_input(cz_session *session, cz_stream *stream, const uint8_t *data, int size)
{
    int taken = 0;
    if (stream == &session->control) {
        return control_input(session, data, size);
    }

    /* First comes the name of the service the initiator wants: {"svc":"<name>"} with a 2-byte length. */
    while (!stream->open && !stream->refused && taken < size) {
        if (stream->preamble_used >= (int)sizeof stream->preamble) {
            stream_reset(session, stream);
            return size;
        }
        stream->preamble[stream->preamble_used++] = data[taken++];
        if (stream->preamble_used >= 2) {
            int length = (stream->preamble[0] << 8) | stream->preamble[1];
            if (length == 0 || length > (int)sizeof stream->preamble - 2) {
                stream_reset(session, stream);
                return size;
            }
            if (stream->preamble_used == 2 + length) {
                cz_span request = { (const char *)stream->preamble + 2, (size_t)length };
                char name[CZ_NAME_SIZE] = "";
                text_member(request, "svc", name, sizeof name);
                service_open(session, stream, name);
                if (session->ended) {
                    return size;
                }
                /* The request was stream data like any other: the peer gets that part of its window back too. */
                stream_consumed(session, stream, (uint32_t)stream->preamble_used);
            }
        }
    }
    if (stream->refused || taken == size) {
        return size;
    }

    int sent = (int)send(stream->fd, (const char *)data + taken, size - taken, 0);
    if (sent < 0) {
        if (cz_socket_would_block()) {
            session->blocked_fd = stream->fd;
            return taken;
        }
        stream_reset(session, stream); /* the local application went away */
        return size;
    }
    session->bytes_received += (uint64_t)sent;
    stream_consumed(session, stream, (uint32_t)sent);
    if (taken + sent < size) {
        session->blocked_fd = stream->fd;
    }
    return taken + sent;
}

static void frame_finished(cz_session *session)
{
    cz_stream *stream = session->frame_stream;
    session->in_frame = false;
    if (stream == NULL || session->ended) {
        return;
    }
    if (session->frame_flags & FLAG_RST) {
        if (stream == &session->control) {
            session_end(session, "SESSION_CLOSED", false);
        } else {
            stream_release(session, stream);
        }
    } else if (session->frame_flags & FLAG_FIN) {
        stream->remote_done = true;
        if (stream == &session->control) {
            session_end(session, "SESSION_CLOSED", false);
        } else if (stream->local_done) {
            stream_release(session, stream);
        } else if (stream->fd >= 0) {
            shutdown(stream->fd, 1); /* no more data for the local application */
        }
    }
}

/* Consumes decrypted bytes. Returns false when a local service cannot take more right now. */
static bool mux_consume(cz_session *session)
{
    const uint8_t *data = session->rx + session->plain_at;
    int available = session->plain_end - session->plain_at;

    if (session->in_frame) {
        int size = available < (int)session->frame_left ? available : (int)session->frame_left;
        int taken = session->frame_stream != NULL ? stream_input(session, session->frame_stream, data, size) : size;
        session->plain_at += taken;
        session->frame_left -= (uint32_t)taken;
        if (session->ended) {
            return true;
        }
        if (taken < size) {
            return false;
        }
        if (session->frame_left == 0) {
            frame_finished(session);
        }
        return true;
    }

    int take = MUX_HEADER - session->mux_header_used;
    if (take > available) {
        take = available;
    }
    memcpy(session->mux_header + session->mux_header_used, data, (size_t)take);
    session->mux_header_used += take;
    session->plain_at += take;
    if (session->mux_header_used < MUX_HEADER) {
        return true;
    }
    session->mux_header_used = 0;

    const uint8_t *header = session->mux_header;
    int type = header[1];
    uint16_t flags = (uint16_t)((header[2] << 8) | header[3]);
    uint32_t id = get32(header + 4);
    uint32_t length = get32(header + 8);
    if (header[0] != 0) {
        session_end(session, "MUX_PROTOCOL_ERROR", false);
        return true;
    }
    if (type == MUX_PING) {
        if (flags & FLAG_SYN) {
            session_send_frame(session, MUX_PING, FLAG_ACK, 0, length, 0);
        }
        return true;
    }
    if (type == MUX_GO_AWAY) {
        session_end(session, length == 0 ? "SESSION_CLOSED" : "MUX_PROTOCOL_ERROR", false);
        return true;
    }
    if ((type != MUX_DATA && type != MUX_WINDOW_UPDATE) || id == 0 || (type == MUX_DATA && length > INITIAL_WINDOW)) {
        session_end(session, "MUX_PROTOCOL_ERROR", false);
        return true;
    }

    cz_stream *stream = session_find_stream(session, id);
    if (flags & FLAG_SYN) {
        /* Only the initiator opens streams, with odd and increasing numbers. */
        if (stream != NULL || id % 2 == 0 || id <= session->last_remote_stream) {
            session_end(session, "MUX_PROTOCOL_ERROR", false);
            return true;
        }
        session->last_remote_stream = id;
        if (!session->control.used) {
            /* The first stream is the control stream: this side states its view of the session at once. */
            stream = &session->control;
            memset(stream, 0, sizeof *stream);
            stream->used = true;
            stream->id = id;
            stream->fd = -1;
            stream->send_window = INITIAL_WINDOW;
            char json[320];
            if (session->direct) {
                snprintf(json, sizeof json, "{\"bind\":{\"sid\":\"%s\",\"grant\":\"%s\",\"role\":\"device\",\"mode\":\"direct\",\"cands\":\"%s\"}}",
                         session->grant.session_id, session->grant_hash, session->d->local_hash);
            } else {
                snprintf(json, sizeof json, "{\"bind\":{\"sid\":\"%s\",\"grant\":\"%s\",\"role\":\"device\",\"mode\":\"e2e-relay\"}}",
                         session->grant.session_id, session->grant_hash);
            }
            if (!stream_send_json(session, stream, 4, json)) {
                return true;
            }
        } else if (!session->bound) {
            session_end(session, "MUX_PROTOCOL_ERROR", false); /* services only after the bind */
            return true;
        } else {
            for (int i = 0; i < CZ_MAX_STREAMS && stream == NULL; i++) {
                if (!session->streams[i].used) {
                    stream = &session->streams[i];
                    memset(stream, 0, sizeof *stream);
                    stream->used = true;
                    stream->id = id;
                    stream->fd = -1;
                    stream->send_window = INITIAL_WINDOW;
                }
            }
            if (stream == NULL) {
                /* Every slot is taken: this stream is refused, the others go on. */
                session_send_frame(session, MUX_WINDOW_UPDATE, FLAG_RST, id, 0, 0);
            }
        }
    }

    session->frame_stream = stream;
    session->frame_flags = flags;
    session->frame_left = type == MUX_DATA ? length : 0;
    session->in_frame = true;
    if (type == MUX_WINDOW_UPDATE && stream != NULL) {
        stream->send_window += length;
    }
    if (session->frame_left == 0) {
        frame_finished(session);
    }
    return true;
}

/* ---- Session: the path below the encryption ------------------------------------------------ */

/* Reads bytes of the path without waiting: the count, 0 when there are none, -1 when it ended. */
static int path_read(cz_session *session, uint8_t *out, int capacity, const char **end_reason)
{
    *end_reason = "PATH_CLOSED";
    if (session->direct) {
        cz_direct *d = session->d;
        if (d->in_offset >= d->in_used) {
            int size = ikcp_recv(d->kcp, (char *)d->in, sizeof d->in);
            if (size <= 0) {
                return d->peer_closed ? -1 : 0;
            }
            d->in_used = size;
            d->in_offset = 0;
        }
        int count = d->in_used - d->in_offset;
        if (count > capacity) {
            count = capacity;
        }
        memcpy(out, d->in + d->in_offset, (size_t)count);
        d->in_offset += count;
        return count;
    }

    for (;;) {
        bool text = false;
        bool end = false;
        int size = cz_ws_read(&session->relay, out, capacity, &text, &end);
        if (size < 0) {
            /* The relay names why it ended a session; "the peer left" is the ordinary end of the path. */
            if (session->relay.close_code >= 4000 && session->relay.close_reason[0] != '\0') {
                *end_reason = session->relay.close_reason;
            }
            return -1;
        }
        if (size == 0 && !end) {
            return 0;
        }
        if (!text && size > 0) {
            return size;
        }
        /* Text frames are the relay's own notices, not session data. */
    }
}

/* Handles what arrived for a session that has a path. */
static void session_pump(cz_session *session)
{
    cz_agent *agent = session->agent;
    const char *reason;

    if (session->phase == PHASE_PAIRING) {
        /* The relay sends one text message, {"t":"paired"}, when both ends are connected. */
        for (;;) {
            bool text = false;
            bool end = false;
            int size = cz_ws_read(&session->relay, session->rx + session->rx_used, (int)sizeof session->rx - session->rx_used - 1, &text, &end);
            if (size < 0) {
                session_end(session, session->relay.close_reason[0] != '\0' ? session->relay.close_reason : "RELAY_UNREACHABLE", false);
                return;
            }
            session->rx_used += size;
            if (!end) {
                if (size == 0) {
                    return;
                }
                continue;
            }
            cz_span message = { (const char *)session->rx, (size_t)session->rx_used };
            char type[16] = "";
            session->rx_used = 0;
            if (text && text_member(message, "t", type, sizeof type) && strcmp(type, "paired") == 0) {
                session_set_phase(session, PHASE_HANDSHAKE);
                break;
            }
        }
    }

    if (session->phase == PHASE_HANDSHAKE) {
        /* The initiator's handshake message: 32 bytes of key agreement and a 16-byte tag, behind a 2-byte length. */
        while (session->rx_used < 2 + CZ_HANDSHAKE_SIZE) {
            int size = path_read(session, session->rx + session->rx_used, 2 + CZ_HANDSHAKE_SIZE - session->rx_used, &reason);
            if (size < 0) {
                session_end(session, strcmp(reason, "PATH_CLOSED") == 0 ? "E2E_HANDSHAKE_FAILED" : reason, false);
                return;
            }
            if (size == 0) {
                return;
            }
            session->rx_used += size;
            if (session->rx_used >= 2 && ((session->rx[0] << 8) | session->rx[1]) != CZ_HANDSHAKE_SIZE) {
                session_end(session, "E2E_HANDSHAKE_FAILED", false);
                return;
            }
        }
        session->rx_used = 0;

        char prologue[160];
        int prologue_size = snprintf(prologue, sizeof prologue, "cz-e2e-shared-key/1|%s|%s", session->grant.session_id, session->grant_hash);
        cz_noise_handshake handshake;
        bool matched = false;
        /* The device may hold several keys; the one the initiator used is found by trying them. */
        for (int i = 0; i < agent->key_count && !matched; i++) {
            matched = cz_noise_respond_begin(&handshake, (const uint8_t *)prologue, (size_t)prologue_size, agent->keys[i], session->rx + 2, CZ_HANDSHAKE_SIZE, NULL);
        }

        uint8_t *answer = session->tx + TX_OFFSET;
        uint8_t ephemeral[CZ_KEY_SIZE];
        cz_random(ephemeral, sizeof ephemeral);
        bool ready = matched && cz_noise_respond_finish(&handshake, ephemeral, NULL, 0, answer, &session->noise);
        memset(ephemeral, 0, sizeof ephemeral);
        memset(&handshake, 0, sizeof handshake);
        /* An empty message in place of the handshake message tells the initiator that no key fits. */
        size_t answer_size = ready ? CZ_HANDSHAKE_SIZE : 0;
        answer[-2] = (uint8_t)(answer_size >> 8);
        answer[-1] = (uint8_t)answer_size;
        bool sent = session->direct ? ikcp_send(session->d->kcp, (const char *)answer - 2, (int)answer_size + 2) >= 0
                                    : cz_ws_send(&session->relay, false, answer - 2, answer_size + 2);
        if (!ready || !sent) {
            if (session->direct && session->d->kcp != NULL) {
                ikcp_flush(session->d->kcp);
            }
            session_end(session, !matched ? "E2E_SHARED_KEY_MISMATCH" : "E2E_HANDSHAKE_FAILED", false);
            return;
        }
        session_set_phase(session, PHASE_BIND);
    }

    if (session->phase < PHASE_BIND) {
        return;
    }

    while (!session->ended) {
        if (session->plain_at < session->plain_end) {
            if (!mux_consume(session)) {
                return; /* a local service is busy; come back when it can take more */
            }
            continue;
        }

        int needed = 2 - session->rx_used;
        int message = 0;
        if (session->rx_used >= 2) {
            message = (session->rx[0] << 8) | session->rx[1];
            if (message < CZ_TAG_SIZE || message > CZ_MAX_PLAINTEXT + CZ_TAG_SIZE) {
                session_end(session, "PATH_CLOSED", false);
                return;
            }
            needed = 2 + message - session->rx_used;
        }
        if (needed > 0) {
            int size = path_read(session, session->rx + session->rx_used, needed, &reason);
            if (size < 0) {
                session_end(session, reason, false);
                return;
            }
            if (size == 0) {
                return;
            }
            session->rx_used += size;
            continue;
        }

        if (!cz_noise_decrypt(&session->noise, session->rx + 2, (size_t)message)) {
            session_end(session, "PATH_CLOSED", false); /* altered on the way */
            return;
        }
        session->plain_at = 2;
        session->plain_end = 2 + message - CZ_TAG_SIZE;
        session->rx_used = 0;
    }
}

/* Passes on what a local service has to say, as far as the peer's window and the path allow. */
static void session_pump_local(cz_session *session, cz_stream *stream)
{
    if (session->direct && ikcp_waitsnd(session->d->kcp) >= CZ_KCP_WINDOW + 8) {
        return; /* the path is full; the data stays in the local socket until it drains */
    }
    uint32_t room = stream->send_window < MAX_DATA ? stream->send_window : MAX_DATA;
    if (room == 0) {
        return;
    }
    int size = (int)recv(stream->fd, (char *)session_payload(session), (int)room, 0);
    if (size > 0) {
        session->bytes_sent += (uint64_t)size;
        stream_send(session, stream, (size_t)size);
    } else if (size == 0) {
        /* The local application finished sending. */
        stream->local_done = true;
        if (session_send_frame(session, MUX_WINDOW_UPDATE, FLAG_FIN | first_frame_flags(stream), stream->id, 0, 0) && stream->remote_done) {
            stream_release(session, stream);
        }
    } else if (!cz_socket_would_block()) {
        stream_reset(session, stream);
    }
}

/* ---- Session: start ----------------------------------------------------------------------- */

static void session_connect_relay(cz_session *session)
{
    cz_agent *agent = session->agent;
    char error[40];
    if (!session->grant.mode_relay || session->grant.relay_url[0] == '\0') {
        session_end(session, "DIRECT_UNAVAILABLE", false);
        return;
    }
    session->direct = false;
    snprintf(agent->scratch, BUFFER_SIZE, "Authorization: Bearer %s\r\nCz-Role: device\r\n", session->token);
    if (!cz_ws_open(&session->relay, session->grant.relay_url, agent->scratch, agent->root_ca, error, sizeof error)) {
        session_end(session, error, false);
        return;
    }
    session->rx_used = 0;
    session_set_phase(session, PHASE_PAIRING);
}

static void session_start_direct(cz_session *session)
{
    cz_agent *agent = session->agent;
    cz_direct *d = (cz_direct *)calloc(1, sizeof *d);
    if (d == NULL) {
        session_connect_relay(session);
        return;
    }
    d->fd = udp_open(&d->ipv6, &d->port);
    if (d->fd < 0) {
        free(d);
        session_connect_relay(session);
        return;
    }
    cz_socket_set_nonblocking(d->fd);

    /* Both endpoints hold the same grant, so both derive the same tag and KCP conversation number. */
    uint8_t digest[CZ_SHA256_SIZE];
    cz_sha256(session->token, strlen(session->token), digest);
    memcpy(d->tag, digest, 8);
    d->conversation = get32(digest + 8) | 1u;

    for (int i = 0; i < agent->stun_count && d->stun_count < 2; i++) {
        char host[64];
        cz_copy(host, sizeof host, agent->stun[i]);
        char *colon = strrchr(host, ':');
        if (colon == NULL) {
            continue;
        }
        *colon = '\0';
        long port = strtol(colon + 1, NULL, 10);
        uint32_t server_address;
        if (port < 1 || port > 65535 || !cz_resolve(host, &server_address)) {
            continue;
        }
        cz_endpoint server = endpoint_v4(server_address, (uint16_t)port);
        d->stun[d->stun_count].server = server;
        cz_random(d->stun[d->stun_count].id, 12);
        d->stun_count++;
    }

    session->d = d;
    session->direct = true;
    d->started = cz_millis();
    session_set_phase(session, PHASE_GATHER);
    stun_send_requests(d);
}

/* The candidate list goes to the initiator through signaling; its hash is confirmed later inside the session. */
static void direct_send_candidates(cz_session *session)
{
    cz_agent *agent = session->agent;
    cz_direct *d = session->d;
    char list[480];
    int length = snprintf(list, sizeof list, "{\"sid\":\"%s\",\"role\":\"device\",\"udp\":[", session->grant.session_id);
    int count = 0;
    char text[64];

    cz_endpoint own = endpoint_v4(cz_local_address(), d->port);
    if (own.address != 0) {
        format_endpoint(own, text, sizeof text);
        length += snprintf(list + length, sizeof list - (size_t)length, "%s\"%s\"", count++ > 0 ? "," : "", text);
    }
    if (d->ipv6) {
        /* Global IPv6 addresses need no NAT traversal: the peer can send to them as they are. */
        uint8_t addresses[MAX_IPV6_ADDRESSES][16];
        int found = cz_local_ipv6(addresses, MAX_IPV6_ADDRESSES);
        for (int i = 0; i < found; i++) {
            cz_endpoint global;
            memset(&global, 0, sizeof global);
            global.ipv6 = true;
            memcpy(global.v6, addresses[i], 16);
            global.port = d->port;
            format_endpoint(global, text, sizeof text);
            length += snprintf(list + length, sizeof list - (size_t)length, "%s\"%s\"", count++ > 0 ? "," : "", text);
        }
    }
    if (agent->include_loopback) {
        length += snprintf(list + length, sizeof list - (size_t)length, "%s\"127.0.0.1:%u\"", count++ > 0 ? "," : "", (unsigned)d->port);
    }
    bool answered = false;
    bool symmetric = false;
    cz_endpoint mapped = endpoint_v4(0, 0);
    for (int i = 0; i < d->stun_count; i++) {
        if (d->stun[i].answered) {
            /* Different answers from different servers: the NAT maps every destination separately. */
            symmetric = symmetric || (answered && !same_endpoint(mapped, d->stun[i].mapped));
            if (!answered) {
                mapped = d->stun[i].mapped;
            }
            answered = true;
        }
    }
    if (answered && !same_endpoint(mapped, own) && !(agent->include_loopback && mapped.port == d->port && mapped.address == htonl(0x7f000001u))) {
        format_endpoint(mapped, text, sizeof text);
        length += snprintf(list + length, sizeof list - (size_t)length, "%s\"%s\"", count++ > 0 ? "," : "", text);
    }
    length += snprintf(list + length, sizeof list - (size_t)length, "],\"nat\":\"%s\"}", !answered ? "unknown" : symmetric ? "symmetric" : "cone");

    const char *offered = strstr(list, "\"udp\"");
    agent_log(agent, "session %s: offering %s", session->grant.session_id, offered != NULL ? offered : list);

    uint8_t digest[CZ_SHA256_SIZE];
    cz_sha256(list, (size_t)length, digest);
    cz_hex(digest, sizeof digest, d->local_hash);

    size_t capacity;
    char *json = signal_buffer(agent, &capacity);
    int written = snprintf(json, capacity, "{\"t\":\"path.candidates\",\"d\":{\"sid\":\"%s\",\"blob\":\"", session->grant.session_id);
    int encoded = cz_base64_encode((const uint8_t *)list, (size_t)length, json + written, capacity - (size_t)written);
    if (encoded > 0) {
        written += encoded;
        written += snprintf(json + written, capacity - (size_t)written, "\"}}");
        signal_send(agent, written);
    }
    session_set_phase(session, PHASE_PUNCH);
}

static void direct_set_remote(cz_session *session, cz_span blob_value)
{
    cz_agent *agent = session->agent;
    cz_direct *d = session->d;
    char encoded[700];
    if (d == NULL || d->remote_known || !cz_json_string(blob_value, encoded, sizeof encoded)) {
        return;
    }
    int length = cz_base64_decode(encoded, strlen(encoded), (uint8_t *)agent->scratch, BUFFER_SIZE - 1);
    if (length <= 0) {
        return;
    }
    agent->scratch[length] = '\0';
    const char *offered = strstr(agent->scratch, "\"udp\"");
    agent_log(agent, "session %s: the app offers %s", session->grant.session_id, offered != NULL ? offered : agent->scratch);
    cz_span list = { agent->scratch, (size_t)length };
    cz_span value;
    char text[CZ_ID_SIZE];
    if (!text_member(list, "sid", text, sizeof text) || strcmp(text, session->grant.session_id) != 0
        || !text_member(list, "role", text, sizeof text) || strcmp(text, "initiator") != 0 || !cz_json_member(list, "udp", &value)) {
        return;
    }
    size_t cursor = 0;
    cz_span item;
    char candidate[64];
    while (d->remote_count < MAX_CANDIDATES && cz_json_next(value, &cursor, &item)) {
        cz_endpoint endpoint;
        if (cz_json_string(item, candidate, sizeof candidate) && parse_endpoint(candidate, &endpoint) && (d->ipv6 || !endpoint.ipv6)
            && !direct_is_candidate(d, endpoint)) {
            d->remote[d->remote_count++] = endpoint;
        }
    }
    uint8_t digest[CZ_SHA256_SIZE];
    cz_sha256(agent->scratch, (size_t)length, digest);
    cz_hex(digest, sizeof digest, d->remote_hash);
    d->remote_known = true;
}

/* What is due on a direct path: STUN retries, probes, KCP's timer, keep-alives, time-outs. */
static void direct_tick(cz_session *session)
{
    cz_direct *d = session->d;
    if (session->phase == PHASE_GATHER) {
        bool all = true;
        for (int i = 0; i < d->stun_count; i++) {
            all = all && d->stun[i].answered;
        }
        if (all || elapsed(d->started, STUN_TIMEOUT_MS)) {
            direct_send_candidates(session);
        } else if (d->requests < 4 && elapsed(d->last_request, 200u << (d->requests - 1))) {
            stun_send_requests(d); /* UDP is lossy: ask again a few times */
        }
        return;
    }

    if (!d->selected) {
        /* Probing the initiator's addresses opens this side's NAT for them. */
        if (d->remote_known && elapsed(d->last_probe, PROBE_INTERVAL_MS)) {
            uint8_t probe[18];
            probe[0] = DGRAM_PROBE;
            memcpy(probe + 1, d->tag, 8);
            probe[9] = 0;
            cz_random(probe + 10, 8);
            for (int i = 0; i < d->learned_count; i++) {
                udp_send(d, probe, sizeof probe, d->learned[i]);
            }
            for (int i = 0; i < d->remote_count; i++) {
                udp_send(d, probe, sizeof probe, d->remote[i]);
            }
            d->last_probe = cz_millis();
        }
        if (elapsed(session->phase_started, DIRECT_TIMEOUT_MS)) {
            session_end(session, "SIGNALING_TIMEOUT", false);
        }
        return;
    }

    ikcp_update(d->kcp, cz_millis());
    if (elapsed(d->last_received, IDLE_TIMEOUT_MS) || d->kcp->state != 0) {
        session_end(session, "PATH_IDLE_TIMEOUT", false);
    } else if (elapsed(d->last_sent, KEEP_ALIVE_MS)) {
        uint8_t keep_alive = DGRAM_KEEP_ALIVE;
        udp_send(d, &keep_alive, 1, d->peer);
        d->last_sent = cz_millis();
    }
}

/* ---- Offers ------------------------------------------------------------------------------- */

static bool grant_key_known(const cz_agent *agent, const char *kid)
{
    for (int i = 0; i < agent->grant_key_count; i++) {
        if (strcmp(agent->grant_keys[i].kid, kid) == 0) {
            return true;
        }
    }
    return false;
}

static void send_answer(cz_agent *agent, const char *session_id, const char *refusal)
{
    size_t capacity;
    char *json = signal_buffer(agent, &capacity);
    int length = refusal == NULL
        ? snprintf(json, capacity, "{\"t\":\"connect.answer\",\"d\":{\"sid\":\"%s\",\"accept\":true}}", session_id)
        : snprintf(json, capacity, "{\"t\":\"connect.answer\",\"d\":{\"sid\":\"%s\",\"accept\":false,\"error\":\"%s\"}}", session_id, refusal);
    signal_send(agent, length);
}

/*
 * The platform says an application wants to connect. The device checks the grant's signature and
 * that the grant is really about this device. Whether the application is to be trusted is not
 * the platform's to say: the handshake proves that it holds the shared key.
 */
static void handle_offer(cz_agent *agent, cz_span data)
{
    char session_id[CZ_ID_SIZE] = "";
    char peer_name[CZ_NAME_SIZE] = "";
    cz_span value;
    cz_span peer;
    bool peer_direct = false;
    size_t token_length = 0;
    char *token = NULL;

    /* Everything needed is copied out first: the buffer the offer is in gets reused below. */
    text_member(data, "sid", session_id, sizeof session_id);
    if (cz_json_member(data, "peer", &peer)) {
        if (!text_member(peer, "name", peer_name, sizeof peer_name)) {
            text_member(peer, "id", peer_name, sizeof peer_name);
        }
        peer_direct = cz_json_member(peer, "caps", &value) && cz_json_contains(value, "path.udp-kcp");
    }
    if (cz_json_member(data, "grant", &value) && value.length > 2) {
        token_length = value.length;
        token = (char *)malloc(token_length);
        if (token != NULL && !cz_json_string(value, token, token_length)) {
            free(token);
            token = NULL;
        }
    }
    if (session_id[0] == '\0' || token == NULL) {
        free(token);
        return;
    }

    /* The keys grants are signed with are fetched when a key appears that is not known yet. */
    char kid[24];
    if (cz_grant_key_id(token, kid, sizeof kid) && !grant_key_known(agent, kid) && (!agent->keys_fetched || elapsed(agent->keys_fetched_at, KEY_REFRESH_MS))) {
        agent->keys_fetched = true;
        agent->keys_fetched_at = cz_millis();
        if (cz_http_request(&agent->api, ".well-known/jwks.json", NULL, agent->root_ca, agent->message, BUFFER_SIZE) == 200) {
            agent->grant_key_count = cz_grant_keys_parse(agent->message, strlen(agent->message), agent->grant_keys, CZ_MAX_GRANT_KEYS);
        }
    }

    cz_session *session = (cz_session *)calloc(1, sizeof *session);
    if (session == NULL) {
        free(token);
        send_answer(agent, session_id, "DEVICE_REJECTED");
        return;
    }
    const char *refusal = cz_grant_verify(token, agent->grant_keys, agent->grant_key_count, agent_now(agent), true, (uint8_t *)agent->scratch, BUFFER_SIZE, &session->grant);
    bool direct = false;
    if (refusal == NULL) {
        direct = session->grant.mode_direct && agent->peer_to_peer && peer_direct;
        if (strcmp(session->grant.session_id, session_id) != 0 || strcmp(session->grant.device_id, agent->device_id) != 0) {
            refusal = "GRANT_INVALID";
        } else if (session->grant.mode_compatibility) {
            refusal = "COMPATIBILITY_NOT_ENABLED"; /* the gateway can read what it forwards; this device never opts in */
        } else if (!session->grant.shared_key || agent->key_count == 0) {
            refusal = "E2E_NO_COMMON_METHOD";
        } else if (!direct && !(session->grant.mode_relay && session->grant.relay_url[0] != '\0')) {
            refusal = "NO_PERMITTED_MODE";
        }
    }
    send_answer(agent, session_id, refusal);
    if (refusal != NULL) {
        agent_log(agent, "refused connection from %s (%s)", peer_name, refusal);
        cz_copy(agent->last_error, sizeof agent->last_error, refusal);
        free(token);
        free(session);
        return;
    }

    /* A new session takes the place of the oldest when every slot is in use. */
    int slot = -1;
    for (int i = 0; i < CZ_MAX_SESSIONS; i++) {
        if (agent->sessions[i] == NULL) {
            slot = i;
        }
    }
    if (slot < 0) {
        slot = 0;
        for (int i = 1; i < CZ_MAX_SESSIONS; i++) {
            if ((int32_t)(agent->sessions[i]->phase_started - agent->sessions[slot]->phase_started) < 0) {
                slot = i;
            }
        }
        session_end(agent->sessions[slot], "SESSION_CLOSED", true);
        session_free(agent->sessions[slot]);
    }
    agent->sessions[slot] = session;

    session->agent = agent;
    session->token = token;
    session->peer_direct = peer_direct;
    session->blocked_fd = -1;
    session->control.fd = -1;
    for (int i = 0; i < CZ_MAX_STREAMS; i++) {
        session->streams[i].fd = -1;
    }
    cz_copy(session->peer_name, sizeof session->peer_name, peer_name);
    uint8_t digest[CZ_SHA256_SIZE];
    cz_sha256(token, strlen(token), digest);
    cz_hex(digest, sizeof digest, session->grant_hash);
    session->lease_expires = session->grant.issued_at + session->grant.lease_seconds;
    session->phase_started = cz_millis();

    /* The device follows the initiator: a direct path if the initiator finds one, the relay if it says so. */
    if (direct) {
        session_start_direct(session);
    } else {
        session_connect_relay(session);
    }
}

static cz_session *find_session(cz_agent *agent, cz_span data)
{
    char session_id[CZ_ID_SIZE];
    if (!text_member(data, "sid", session_id, sizeof session_id)) {
        return NULL;
    }
    for (int i = 0; i < CZ_MAX_SESSIONS; i++) {
        if (agent->sessions[i] != NULL && !agent->sessions[i]->ended && strcmp(agent->sessions[i]->grant.session_id, session_id) == 0) {
            return agent->sessions[i];
        }
    }
    return NULL;
}

/* ---- Signaling: receiving ------------------------------------------------------------------ */

static void signal_close(cz_agent *agent)
{
    if (agent->signal_open) {
        cz_ws_close(&agent->signal, 1000);
    }
    agent->signal_open = false;
    agent->welcomed = false;
    agent->message_used = 0;
    agent->message_overflow = false;
    if (agent->state == CZ_STATE_ONLINE) {
        agent->state = CZ_STATE_OFFLINE;
    }
}

static bool is_final(const char *code)
{
    return strcmp(code, "DEVICE_REVOKED") == 0 || strcmp(code, "CREDENTIAL_REVOKED") == 0 || strcmp(code, "UNAUTHENTICATED") == 0
        || strcmp(code, "IDENTITY_NOT_REGISTERED") == 0 || strcmp(code, "INVALID_REQUEST") == 0 || strcmp(code, "CONFLICT") == 0;
}

static void agent_refused(cz_agent *agent, const char *code)
{
    cz_copy(agent->last_error, sizeof agent->last_error, code);
    agent_log(agent, "the platform does not accept this device (%s); stopped", code);
    for (int i = 0; i < CZ_MAX_SESSIONS; i++) {
        if (agent->sessions[i] != NULL) {
            session_end(agent->sessions[i], code, true);
        }
    }
    signal_close(agent);
    agent->state = CZ_STATE_REFUSED;
}

static void handle_signal(cz_agent *agent, cz_span message)
{
    char type[24] = "";
    cz_span data = { NULL, 0 };
    cz_span value;
    text_member(message, "t", type, sizeof type);
    cz_json_member(message, "d", &data);

    if (strcmp(type, "welcome") == 0) {
        int64_t server_time = 0;
        if (cz_json_member(data, "serverTime", &value) && cz_json_int(value, &server_time) && server_time > 0) {
            agent->clock_offset = server_time - (int64_t)(cz_millis() / 1000u);
        }
        agent->stun_count = 0;
        if (cz_json_member(data, "stunServers", &value)) {
            size_t cursor = 0;
            cz_span item;
            while (agent->stun_count < 2 && cz_json_next(value, &cursor, &item)) {
                if (cz_json_string(item, agent->stun[agent->stun_count], sizeof agent->stun[0])) {
                    agent->stun_count++;
                }
            }
        }
        agent->welcomed = true;
        agent->state = CZ_STATE_ONLINE;
        agent->backoff = 1000;
        agent->last_error[0] = '\0';
        agent_log(agent, "connected as device '%s'", agent->name);
        /* The network is up: let it acquire IPv6 addresses, which the direct path offers once there are global ones. */
        cz_ipv6_enable();
    } else if (strcmp(type, "error") == 0 && !agent->welcomed) {
        char code[40] = "INVALID_REQUEST";
        text_member(data, "code", code, sizeof code);
        if (is_final(code)) {
            agent_refused(agent, code);
        } else {
            cz_copy(agent->last_error, sizeof agent->last_error, code);
            signal_close(agent);
        }
    } else if (strcmp(type, "connect.offer") == 0) {
        handle_offer(agent, data);
    } else if (strcmp(type, "path.candidates") == 0) {
        cz_session *session = find_session(agent, data);
        if (session != NULL && cz_json_member(data, "blob", &value)) {
            direct_set_remote(session, value);
        }
    } else if (strcmp(type, "path.fallback") == 0) {
        cz_session *session = find_session(agent, data);
        /* The initiator found no direct path; a handshake that was under way on one is abandoned. */
        if (session != NULL && session->direct && !session->established) {
            char stranger[64] = "none";
            if (session->d != NULL && endpoint_set(session->d->unannounced)) {
                format_endpoint(session->d->unannounced, stranger, sizeof stranger);
            }
            agent_log(agent, "session %s: no direct path, using the relay (probes received: %d, from an unannounced address: %s)",
                      session->grant.session_id, session->d != NULL ? session->d->probes_received : 0, stranger);
            direct_close(session->d, false);
            session->d = NULL;
            /* Whatever had begun on the direct path is void; on the relay everything starts again. */
            session->rx_used = 0;
            session->plain_at = session->plain_end = 0;
            session->mux_header_used = 0;
            session->in_frame = false;
            session->frame_stream = NULL;
            session->last_remote_stream = 0;
            session->control_used = 0;
            session->bound = false;
            memset(&session->control, 0, sizeof session->control);
            session->control.fd = -1;
            memset(&session->noise, 0, sizeof session->noise);
            session_connect_relay(session);
        }
    } else if (strcmp(type, "revoke") == 0) {
        char reason[40] = "SESSION_REVOKED";
        cz_span list;
        bool all = !cz_json_member(data, "sids", &list) || list.length < 2 || list.at[0] != '[';
        text_member(data, "reason", reason, sizeof reason);
        for (int i = 0; i < CZ_MAX_SESSIONS; i++) {
            cz_session *session = agent->sessions[i];
            if (session != NULL && !session->ended && (all || cz_json_contains(list, session->grant.session_id))) {
                session_end(session, reason, true);
            }
        }
    }
}

static void signal_pump(cz_agent *agent)
{
    while (agent->signal_open) {
        bool text = false;
        bool end = false;
        int room = BUFFER_SIZE - 1 - agent->message_used;
        uint8_t discard[64];
        int size = room > 0 ? cz_ws_read(&agent->signal, (uint8_t *)agent->message + agent->message_used, room, &text, &end)
                            : cz_ws_read(&agent->signal, discard, sizeof discard, &text, &end);
        if (size < 0) {
            char reason[40];
            cz_copy(reason, sizeof reason, agent->signal.close_reason);
            agent_log(agent, "disconnected from the platform (%s)", reason[0] != '\0' ? reason : "connection lost");
            if (is_final(reason) && strcmp(reason, "CONFLICT") != 0 && strcmp(reason, "INVALID_REQUEST") != 0) {
                agent_refused(agent, reason);
            } else {
                signal_close(agent);
                if (strcmp(reason, "CONFLICT") == 0) {
                    /* Another device logged in under this name. Do not fight over it every second. */
                    agent_log(agent, "another device is using the name '%s'", agent->name);
                    cz_copy(agent->last_error, sizeof agent->last_error, reason);
                    agent->backoff = 15000;
                }
            }
            return;
        }
        if (size > 0 || end) {
            agent->last_received = cz_millis();
        }
        if (room > 0) {
            agent->message_used += size;
        } else if (size > 0) {
            agent->message_overflow = true; /* longer than anything this device acts on: skipped */
        }
        if (end) {
            int length = agent->message_used;
            bool usable = !agent->message_overflow && text;
            agent->message_used = 0;
            agent->message_overflow = false;
            if (usable) {
                agent->message[length] = '\0';
                cz_span message = { agent->message, (size_t)length };
                handle_signal(agent, message);
            }
        } else if (size == 0) {
            return;
        }
    }
}

/* ---- Connecting to the platform ------------------------------------------------------------ */

static void agent_connect(cz_agent *agent)
{
    /* 1. Log in with the device key and the name: the answer is a short-lived token. */
    int length = snprintf(agent->scratch, BUFFER_SIZE, "{\"key\":");
    length += cz_json_quote(agent->scratch + length, BUFFER_SIZE - (size_t)length, agent->device_key);
    length += snprintf(agent->scratch + length, BUFFER_SIZE - (size_t)length, ",\"name\":");
    length += cz_json_quote(agent->scratch + length, BUFFER_SIZE - (size_t)length, agent->name);
    length += snprintf(agent->scratch + length, BUFFER_SIZE - (size_t)length, ",\"platform\":");
    length += cz_json_quote(agent->scratch + length, BUFFER_SIZE - (size_t)length, agent->platform);
    snprintf(agent->scratch + length, BUFFER_SIZE - (size_t)length, ",\"agentVersion\":\"" CZ_VERSION "\"}");

    int status = cz_http_request(&agent->api, "v1/auth/device-key/token", agent->scratch, agent->root_ca, agent->message, BUFFER_SIZE);
    cz_span response = { agent->message, status > 0 ? strlen(agent->message) : 0 };
    cz_span value;
    if (status != 200) {
        char code[40];
        /* Only the API names its refusals. An answer without a code comes from something in between
           (a proxy while the API restarts, a captive portal) and is a passing failure. */
        if (status < 0) {
            cz_copy(code, sizeof code, "SIGNALING_UNAVAILABLE");
        } else if (!text_member(response, "error", code, sizeof code)) {
            cz_copy(code, sizeof code, status == 401 ? "UNAUTHENTICATED" : "SIGNALING_UNAVAILABLE");
        }
        if (status > 0 && is_final(code)) {
            agent_refused(agent, code);
        } else {
            cz_copy(agent->last_error, sizeof agent->last_error, code);
            agent_log(agent, "platform unavailable (%s); retrying in %u s", code, (unsigned)(agent->backoff / 1000u));
        }
        return;
    }
    int64_t server_time = 0;
    if (!text_member(response, "endpointId", agent->device_id, sizeof agent->device_id) || !cz_json_member(response, "accessToken", &value)) {
        cz_copy(agent->last_error, sizeof agent->last_error, "INVALID_REQUEST");
        agent_log(agent, "the platform's answer to the login was not understood; retrying in %u s", (unsigned)(agent->backoff / 1000u));
        return;
    }
    cz_span token = value;
    if (cz_json_member(response, "serverTime", &value) && cz_json_int(value, &server_time) && server_time > 0) {
        agent->clock_offset = server_time - (int64_t)(cz_millis() / 1000u);
    }

    /* 2. Open the signaling channel with that token. */
    char url[320];
    snprintf(url, sizeof url, "%s://%s:%u%s/v1/signal", agent->api.secure ? "wss" : "ws", agent->api.host, (unsigned)agent->api.port,
             strcmp(agent->api.path, "/") == 0 ? "" : agent->api.path);
    if (token.length < 3 || token.length > BUFFER_SIZE - 64) {
        return;
    }
    snprintf(agent->scratch, BUFFER_SIZE, "Authorization: Bearer %.*s\r\n", (int)token.length - 2, token.at + 1);
    char error[40];
    if (!cz_ws_open(&agent->signal, url, agent->scratch, agent->root_ca, error, sizeof error)) {
        cz_copy(agent->last_error, sizeof agent->last_error, strcmp(error, "RELAY_UNREACHABLE") == 0 ? "SIGNALING_UNAVAILABLE" : error);
        agent_log(agent, "signaling unavailable (%s); retrying in %u s", agent->last_error, (unsigned)(agent->backoff / 1000u));
        return;
    }
    agent->signal_open = true;
    agent->welcomed = false;
    agent->connected_at = agent->last_received = agent->last_ping = cz_millis();

    /* 3. Say what this device can do and which services it declares. Targets are never sent. */
    size_t capacity;
    char *json = signal_buffer(agent, &capacity);
    length = snprintf(json, capacity, "{\"t\":\"hello\",\"id\":\"1\",\"d\":{\"caps\":[\"mux.yamux\",\"path.relay-ws\",\"e2e.shared-key\"%s],\"agentVersion\":\"" CZ_VERSION "\",\"platform\":",
                      agent->peer_to_peer ? ",\"path.udp-kcp\"" : "");
    length += cz_json_quote(json + length, capacity - (size_t)length, agent->platform);
    length += snprintf(json + length, capacity - (size_t)length, ",\"services\":[");
    for (int i = 0; i < agent->service_count; i++) {
        length += snprintf(json + length, capacity - (size_t)length, "%s{\"name\":", i > 0 ? "," : "");
        length += cz_json_quote(json + length, capacity - (size_t)length, agent->services[i].name);
        length += snprintf(json + length, capacity - (size_t)length, ",\"protocol\":\"%s\",\"compat\":false}", agent->services[i].protocol);
    }
    length += snprintf(json + length, capacity - (size_t)length, "]}}");
    if (!signal_send(agent, length)) {
        signal_close(agent);
    }
}

/* ---- The loop ------------------------------------------------------------------------------ */

static void add_fd(int fd, fd_set *set, int *highest)
{
    if (fd >= 0) {
        FD_SET(fd, set);
        if (fd > *highest) {
            *highest = fd;
        }
    }
}

void cz_agent_poll(cz_agent *agent, int max_wait_ms)
{
    if (agent->state == CZ_STATE_REFUSED) {
        cz_sleep_ms(max_wait_ms > 0 ? max_wait_ms : 1);
        return;
    }

    /* Connect when it is time to. */
    if (!agent->signal_open) {
        if ((int32_t)(cz_millis() - agent->next_attempt) < 0) {
            cz_sleep_ms(max_wait_ms < 50 ? max_wait_ms : 50);
        } else {
            agent_connect(agent);
            if (!agent->signal_open && agent->state != CZ_STATE_REFUSED) {
                uint8_t jitter[2];
                cz_random(jitter, sizeof jitter);
                /* Jitter keeps a fleet of devices from reconnecting in the same instant after an outage. */
                agent->next_attempt = cz_millis() + agent->backoff + (uint32_t)(((jitter[0] << 8) | jitter[1]) % 500);
                agent->backoff = agent->backoff * 2 > 30000 ? 30000 : agent->backoff * 2;
            }
        }
    }

    /* Wait until something can be done. */
    fd_set readable;
    fd_set writable;
    int highest = -1;
    bool immediately = false;
    bool direct_active = false;
    FD_ZERO(&readable);
    FD_ZERO(&writable);
    if (agent->signal_open) {
        add_fd(cz_ws_fd(&agent->signal), &readable, &highest);
        immediately = immediately || cz_ws_pending(&agent->signal);
    }
    for (int i = 0; i < CZ_MAX_SESSIONS; i++) {
        cz_session *session = agent->sessions[i];
        if (session == NULL || session->ended) {
            immediately = immediately || session != NULL;
            continue;
        }
        if (session->direct) {
            add_fd(session->d->fd, &readable, &highest);
            direct_active = true;
        } else if (session->relay.conn != NULL) {
            if (session->blocked_fd < 0) {
                add_fd(cz_ws_fd(&session->relay), &readable, &highest);
                immediately = immediately || cz_ws_pending(&session->relay);
            }
        }
        if (session->blocked_fd >= 0) {
            add_fd(session->blocked_fd, &writable, &highest);
        }
        /* Local services are only listened to while the path can take what they say. */
        bool path_full = session->direct && session->d->selected && ikcp_waitsnd(session->d->kcp) >= CZ_KCP_WINDOW + 8;
        for (int k = 0; k < CZ_MAX_STREAMS && session->phase == PHASE_OPEN && !path_full; k++) {
            cz_stream *stream = &session->streams[k];
            if (stream->used && stream->open && !stream->local_done && stream->send_window > 0) {
                add_fd(stream->fd, &readable, &highest);
            }
        }
    }
    int wait_ms = immediately ? 0 : direct_active && max_wait_ms > 10 ? 10 : max_wait_ms;
    if (highest >= 0) {
        struct timeval wait = { wait_ms / 1000, (wait_ms % 1000) * 1000 };
        if (select(highest + 1, &readable, &writable, NULL, &wait) < 0) {
            FD_ZERO(&readable);
            FD_ZERO(&writable);
        }
    } else if (agent->signal_open) {
        cz_sleep_ms(wait_ms > 0 ? wait_ms : 1);
    }

    /* The platform. */
    if (agent->signal_open) {
        signal_pump(agent);
    }
    if (agent->signal_open) {
        if (!agent->welcomed && elapsed(agent->connected_at, HELLO_TIMEOUT_MS)) {
            signal_close(agent);
        } else if (elapsed(agent->last_received, SILENCE_LIMIT_MS)) {
            agent_log(agent, "the platform went silent; reconnecting");
            signal_close(agent);
        } else if (agent->welcomed && elapsed(agent->last_ping, PING_INTERVAL_MS)) {
            size_t capacity;
            char *json = signal_buffer(agent, &capacity);
            agent->last_ping = cz_millis();
            if (!signal_send(agent, snprintf(json, capacity, "{\"t\":\"ping\",\"id\":\"k%u\"}", (unsigned)++agent->message_id))) {
                signal_close(agent);
            }
        }
        if (!agent->signal_open) {
            agent->next_attempt = cz_millis() + agent->backoff;
        }
    }

    /* The sessions. */
    for (int i = 0; i < CZ_MAX_SESSIONS; i++) {
        cz_session *session = agent->sessions[i];
        if (session == NULL) {
            continue;
        }
        if (!session->ended && session->direct) {
            direct_input(session);
            if (!session->ended && session->d != NULL) {
                direct_tick(session);
            }
        }
        if (!session->ended && session->blocked_fd >= 0 && FD_ISSET(session->blocked_fd, &writable)) {
            session->blocked_fd = -1;
        }
        if (!session->ended && session->blocked_fd < 0 && (session->relay.conn != NULL || (session->d != NULL && session->d->selected))) {
            session_pump(session);
        }
        for (int k = 0; k < CZ_MAX_STREAMS && !session->ended && session->phase == PHASE_OPEN; k++) {
            cz_stream *stream = &session->streams[k];
            if (stream->used && stream->open && !stream->local_done && stream->fd >= 0 && FD_ISSET(stream->fd, &readable)) {
                session_pump_local(session, stream);
            }
        }
        if (!session->ended && session->direct && session->d != NULL && session->d->selected) {
            ikcp_flush(session->d->kcp); /* what was just written leaves now rather than at the next tick */
        }
        if (!session->ended) {
            if (session->phase == PHASE_PAIRING && elapsed(session->phase_started, PAIR_TIMEOUT_MS)) {
                session_end(session, "RELAY_PEER_TIMEOUT", false);
            } else if ((session->phase == PHASE_HANDSHAKE || session->phase == PHASE_BIND) && elapsed(session->phase_started, HANDSHAKE_TIMEOUT_MS)) {
                session_end(session, "E2E_HANDSHAKE_FAILED", false);
            } else if (session->established && agent_now(agent) >= session->lease_expires + LEASE_GRACE_SECONDS) {
                /* A session whose authorisation ran out is ended, whatever the platform or the peer say. */
                session_end(session, "LEASE_EXPIRED", true);
            }
        }
        if (session->ended) {
            session_free(session);
        }
    }
}

void cz_agent_run(cz_agent *agent)
{
    while (!agent->stop) {
        cz_agent_poll(agent, 100);
    }
    for (int i = 0; i < CZ_MAX_SESSIONS; i++) {
        if (agent->sessions[i] != NULL) {
            session_end(agent->sessions[i], "SESSION_CLOSED", true);
            session_free(agent->sessions[i]);
        }
    }
    signal_close(agent);
}

void cz_agent_stop(cz_agent *agent)
{
    agent->stop = true;
}

bool cz_agent_stopping(const cz_agent *agent)
{
    return agent->stop;
}

void cz_agent_get_status(const cz_agent *agent, cz_status *out)
{
    memset(out, 0, sizeof *out);
    out->state = agent->state;
    for (int i = 0; i < CZ_MAX_SESSIONS; i++) {
        if (agent->sessions[i] != NULL && agent->sessions[i]->established) {
            out->sessions++;
        }
    }
    cz_copy(out->last_error, sizeof out->last_error, agent->last_error);
    cz_copy(out->device_id, sizeof out->device_id, agent->device_id);
}

cz_agent *cz_agent_create(const cz_config *config)
{
    cz_agent *agent = (cz_agent *)calloc(1, sizeof *agent);
    if (agent == NULL || config == NULL) {
        free(agent);
        return NULL;
    }
    agent->log = config->log;
    agent->log_user = config->log_user;
    agent->backoff = 1000;
    agent->next_attempt = cz_millis();
    agent->peer_to_peer = !config->disable_peer_to_peer;
    agent->include_loopback = config->include_loopback;
    cz_copy(agent->platform, sizeof agent->platform, config->platform != NULL ? config->platform : cz_platform_name());

    const char *problem = NULL;
    if (!cz_url_parse(config->api_url != NULL ? config->api_url : CZ_DEFAULT_API_URL, &agent->api)) {
        problem = "the API address is not a valid http(s) URL";
    } else if (config->device_key == NULL || strncmp(config->device_key, "czd_", 4) != 0 || strlen(config->device_key) >= sizeof agent->device_key) {
        problem = "the device key is missing; it starts with czd_ and is created in the workspace";
    } else if (config->name == NULL || config->name[0] == '\0' || strlen(config->name) >= sizeof agent->name) {
        problem = "the device needs a name of at most 60 characters";
    }
    for (int i = 0; problem == NULL && i < CZ_MAX_SHARED_KEYS; i++) {
        if (config->shared_keys[i] != NULL) {
            if (!cz_shared_key_parse(config->shared_keys[i], agent->keys[agent->key_count])) {
                problem = "a shared key is not valid; it looks like czs_ followed by 43 characters";
            } else {
                agent->key_count++;
            }
        }
    }
    if (problem == NULL && agent->key_count == 0) {
        problem = "the device needs a shared key: without one nobody can reach it end to end";
    }
    for (int i = 0; problem == NULL && i < CZ_MAX_SERVICES; i++) {
        const cz_service *service = &config->services[i];
        if (service->name == NULL) {
            continue;
        }
        cz_service_entry *entry = &agent->services[agent->service_count];
        if (service->name[0] == '\0' || strlen(service->name) >= sizeof entry->name || service->port == 0
            || (service->host != NULL && strlen(service->host) >= sizeof entry->host)) {
            problem = "a service needs a name of at most 60 characters and a port";
            break;
        }
        cz_copy(entry->name, sizeof entry->name, service->name);
        cz_copy(entry->host, sizeof entry->host, service->host != NULL ? service->host : "127.0.0.1");
        cz_copy(entry->protocol, sizeof entry->protocol, service->protocol != NULL ? service->protocol : "tcp");
        entry->port = service->port;
        agent->service_count++;
    }
    if (problem != NULL) {
        agent_log(agent, "connectivitizer: %s", problem);
        free(agent);
        return NULL;
    }

    cz_copy(agent->device_key, sizeof agent->device_key, config->device_key);
    cz_copy(agent->name, sizeof agent->name, config->name);
    if (config->root_ca_pem != NULL) {
        size_t size = strlen(config->root_ca_pem) + 1;
        agent->root_ca = (char *)malloc(size);
        if (agent->root_ca != NULL) {
            memcpy(agent->root_ca, config->root_ca_pem, size);
        }
    }
    return agent;
}

void cz_agent_destroy(cz_agent *agent)
{
    if (agent == NULL) {
        return;
    }
    for (int i = 0; i < CZ_MAX_SESSIONS; i++) {
        if (agent->sessions[i] != NULL) {
            session_end(agent->sessions[i], "SESSION_CLOSED", true);
            session_free(agent->sessions[i]);
        }
    }
    signal_close(agent);
    memset(agent->keys, 0, sizeof agent->keys);
    free(agent->root_ca);
    free(agent);
}
