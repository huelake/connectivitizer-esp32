/* URLs, a minimal HTTP client and a WebSocket client (RFC 6455) over a connection of the port. */
#include "cz_internal.h"

#include <stdio.h>
#include <stdlib.h>

#define CONNECT_TIMEOUT_MS 10000
#define IO_TIMEOUT_MS 15000

bool cz_url_parse(const char *text, cz_url *out)
{
    memset(out, 0, sizeof *out);
    const char *rest;
    if (strncmp(text, "https://", 8) == 0 || strncmp(text, "wss://", 6) == 0) {
        out->secure = true;
        rest = strstr(text, "://") + 3;
    } else if (strncmp(text, "http://", 7) == 0 || strncmp(text, "ws://", 5) == 0) {
        rest = strstr(text, "://") + 3;
    } else {
        return false;
    }

    const char *slash = strchr(rest, '/');
    size_t authority = slash != NULL ? (size_t)(slash - rest) : strlen(rest);
    const char *colon = NULL;
    for (size_t i = 0; i < authority; i++) {
        if (rest[i] == ':') {
            colon = rest + i;
        }
    }
    size_t host_length = colon != NULL ? (size_t)(colon - rest) : authority;
    if (host_length == 0 || host_length >= sizeof out->host) {
        return false;
    }
    memcpy(out->host, rest, host_length);
    out->port = out->secure ? 443 : 80;
    if (colon != NULL) {
        long port = strtol(colon + 1, NULL, 10);
        if (port < 1 || port > 65535) {
            return false;
        }
        out->port = (uint16_t)port;
    }

    cz_copy(out->path, sizeof out->path, slash != NULL ? slash : "/");
    size_t path_length = strlen(out->path);
    if (slash != NULL && strlen(slash) >= sizeof out->path) {
        return false;
    }
    while (path_length > 1 && out->path[path_length - 1] == '/') {
        out->path[--path_length] = '\0';
    }
    return true;
}

/* Waits until the connection has something to read, at most until `deadline` (in cz_millis). */
static bool wait_readable(cz_conn *conn, uint32_t deadline)
{
    if (cz_conn_pending(conn)) {
        return true;
    }
    int32_t left = (int32_t)(deadline - cz_millis());
    if (left <= 0) {
        return false;
    }
    fd_set readable;
    FD_ZERO(&readable);
    int fd = cz_conn_fd(conn);
    FD_SET(fd, &readable);
    struct timeval wait = { left / 1000, (left % 1000) * 1000 };
    return select(fd + 1, &readable, NULL, NULL, &wait) > 0;
}

/*
 * Reads until the end of the header block. Returns the bytes read so far, or -1. With `exact`
 * nothing beyond the header block is read: what follows the answer to a WebSocket request is
 * already the first frame, and it can arrive in the same instant.
 */
static int read_head(cz_conn *conn, char *buffer, int capacity, int *head_length, bool exact)
{
    uint32_t deadline = cz_millis() + IO_TIMEOUT_MS;
    int used = 0;
    while (used < capacity - 1) {
        if (!wait_readable(conn, deadline)) {
            return -1;
        }
        int received = cz_conn_read(conn, (uint8_t *)buffer + used, exact ? 1 : capacity - 1 - used);
        if (received < 0) {
            return -1;
        }
        used += received;
        buffer[used] = '\0';
        char *end = strstr(buffer, "\r\n\r\n");
        if (end != NULL) {
            *head_length = (int)(end - buffer) + 4;
            return used;
        }
    }
    return -1;
}

/* The value of a header in a header block, or NULL. The comparison ignores case. */
static const char *find_header(const char *head, const char *name, size_t *length)
{
    size_t name_length = strlen(name);
    for (const char *line = strstr(head, "\r\n"); line != NULL; line = strstr(line + 2, "\r\n")) {
        const char *at = line + 2;
        size_t i = 0;
        while (i < name_length && at[i] != '\0' && (at[i] | 0x20) == (name[i] | 0x20)) {
            i++;
        }
        if (i == name_length && at[i] == ':') {
            const char *value = at + i + 1;
            while (*value == ' ') {
                value++;
            }
            const char *end = strstr(value, "\r\n");
            *length = end != NULL ? (size_t)(end - value) : strlen(value);
            return value;
        }
    }
    return NULL;
}

/* Removes the framing of a chunked body in place. False when the body is incomplete or malformed. */
static bool unchunk(char *body, int length)
{
    int in = 0;
    int out = 0;
    for (;;) {
        char *end = NULL;
        long size = strtol(body + in, &end, 16);
        if (end == body + in || size < 0) {
            return false;
        }
        char *line = strstr(end, "\r\n"); /* skips chunk extensions */
        if (line == NULL) {
            return false;
        }
        in = (int)(line - body) + 2;
        if (size == 0) {
            body[out] = '\0';
            return true;
        }
        if (in + size + 2 > length) {
            return false;
        }
        memmove(body + out, body + in, (size_t)size);
        out += (int)size;
        in += (int)size + 2;
    }
}

int cz_http_request(const cz_url *url, const char *path_suffix, const char *body, const char *root_ca, char *response, size_t capacity)
{
    cz_conn *conn = cz_conn_open(url->host, url->port, url->secure, root_ca, CONNECT_TIMEOUT_MS);
    if (conn == NULL) {
        return -1;
    }

    int status = -1;
    char head[512];
    size_t body_length = body != NULL ? strlen(body) : 0;
    int head_length = snprintf(head, sizeof head, "%s %s/%s HTTP/1.1\r\nHost: %s:%u\r\nAccept: application/json\r\nConnection: close\r\n",
                               body != NULL ? "POST" : "GET", strcmp(url->path, "/") == 0 ? "" : url->path, path_suffix, url->host, (unsigned)url->port);
    if (body != NULL && head_length > 0 && (size_t)head_length < sizeof head) {
        head_length += snprintf(head + head_length, sizeof head - (size_t)head_length, "Content-Type: application/json\r\nContent-Length: %u\r\n", (unsigned)body_length);
    }
    if (head_length > 0 && (size_t)head_length < sizeof head) {
        head_length += snprintf(head + head_length, sizeof head - (size_t)head_length, "\r\n");
    }
    if (head_length <= 0 || (size_t)head_length >= sizeof head
        || !cz_conn_write(conn, (const uint8_t *)head, (size_t)head_length, IO_TIMEOUT_MS)
        || (body != NULL && !cz_conn_write(conn, (const uint8_t *)body, body_length, IO_TIMEOUT_MS))) {
        cz_conn_close(conn);
        return -1;
    }

    int response_head = 0;
    int used = read_head(conn, response, (int)capacity, &response_head, false);
    if (used > 0 && strncmp(response, "HTTP/1.", 7) == 0 && strlen(response) > 12) {
        status = atoi(response + 9);
        size_t value_length = 0;
        const char *declared = find_header(response, "content-length", &value_length);
        long expected = declared != NULL ? strtol(declared, NULL, 10) : -1;
        const char *encoding = find_header(response, "transfer-encoding", &value_length);
        bool chunked = encoding != NULL && value_length >= 7 && (encoding[0] | 0x20) == 'c';

        /* Keep only the body, then read the rest of it. */
        int have = used - response_head;
        memmove(response, response + response_head, (size_t)have);
        uint32_t deadline = cz_millis() + IO_TIMEOUT_MS;
        while ((expected < 0 || have < expected) && have < (int)capacity - 1) {
            if (!wait_readable(conn, deadline)) {
                break;
            }
            int received = cz_conn_read(conn, (uint8_t *)response + have, (int)capacity - 1 - have);
            if (received < 0) {
                break;
            }
            have += received;
        }
        response[have] = '\0';
        if (expected >= 0 && have < expected) {
            status = -1; /* cut off, or larger than the buffer: not usable */
        }
        if (chunked && !unchunk(response, have)) {
            status = -1;
        }
    }
    cz_conn_close(conn);
    return status;
}

/* ---- WebSocket ---------------------------------------------------------------------------- */

bool cz_ws_open(cz_ws *ws, const char *url_text, const char *headers, const char *root_ca, char *error, size_t error_capacity)
{
    cz_url url;
    memset(ws, 0, sizeof *ws);
    cz_copy(error, error_capacity, "RELAY_UNREACHABLE");
    if (!cz_url_parse(url_text, &url)) {
        return false;
    }
    cz_conn *conn = cz_conn_open(url.host, url.port, url.secure, root_ca, CONNECT_TIMEOUT_MS);
    if (conn == NULL) {
        return false;
    }

    /* The key only has to be unpredictable enough for intermediaries; the server's echo of it is not checked. */
    uint8_t nonce[16];
    char key[28];
    cz_random(nonce, sizeof nonce);
    cz_base64_encode(nonce, sizeof nonce, key, sizeof key);

    char buffer[1024];
    int length = snprintf(buffer, sizeof buffer,
                          "GET %s HTTP/1.1\r\nHost: %s:%u\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n",
                          url.path, url.host, (unsigned)url.port, key);
    bool sent = length > 0 && (size_t)length < sizeof buffer && cz_conn_write(conn, (const uint8_t *)buffer, (size_t)length, IO_TIMEOUT_MS);
    if (sent && headers != NULL) {
        sent = cz_conn_write(conn, (const uint8_t *)headers, strlen(headers), IO_TIMEOUT_MS);
    }
    sent = sent && cz_conn_write(conn, (const uint8_t *)"\r\n", 2, IO_TIMEOUT_MS);

    int head_length = 0;
    int used = sent ? read_head(conn, buffer, (int)sizeof buffer, &head_length, true) : -1;
    if (used < 0 || strncmp(buffer, "HTTP/1.1 101", 12) != 0) {
        if (used > 0) {
            /* The server answered with an ordinary response: it says why in a header, or by its status. */
            size_t value_length = 0;
            const char *named = find_header(buffer, "cz-error", &value_length);
            int status = atoi(buffer + 9);
            if (named != NULL && value_length < error_capacity) {
                memcpy(error, named, value_length);
                error[value_length] = '\0';
            } else {
                cz_copy(error, error_capacity, status == 401 ? "UNAUTHENTICATED" : status == 403 ? "FORBIDDEN" : "RELAY_REJECTED");
            }
        }
        cz_conn_close(conn);
        return false;
    }

    ws->conn = conn;
    error[0] = '\0';
    return true;
}

int cz_ws_fd(const cz_ws *ws)
{
    return ws->conn != NULL ? cz_conn_fd(ws->conn) : -1;
}

bool cz_ws_pending(cz_ws *ws)
{
    return ws->conn != NULL && cz_conn_pending(ws->conn);
}

static void ws_fail(cz_ws *ws, uint16_t code, const char *reason)
{
    if (!ws->closed) {
        ws->closed = true;
        ws->close_code = code;
        cz_copy(ws->close_reason, sizeof ws->close_reason, reason);
    }
}

/* Sends a frame whose payload is at most 125 bytes: pong and close. */
static void ws_send_control(cz_ws *ws, uint8_t opcode, const uint8_t *payload, size_t size)
{
    uint8_t frame[6 + 125];
    uint8_t mask[4];
    if (ws->conn == NULL || size > 125) {
        return;
    }
    cz_random(mask, sizeof mask);
    frame[0] = (uint8_t)(0x80 | opcode);
    frame[1] = (uint8_t)(0x80 | size);
    memcpy(frame + 2, mask, 4);
    for (size_t i = 0; i < size; i++) {
        frame[6 + i] = (uint8_t)(payload[i] ^ mask[i & 3]);
    }
    cz_conn_write(ws->conn, frame, 6 + size, IO_TIMEOUT_MS);
}

int cz_ws_read(cz_ws *ws, uint8_t *out, int capacity, bool *text, bool *end)
{
    *end = false;
    *text = false;
    while (!ws->closed && ws->conn != NULL) {
        if (ws->remaining == 0 && ws->header_used >= 0) {
            /* Collect the frame header: 2 bytes, then 0, 2 or 8 more for the length (servers do not mask). */
            int needed = 2;
            if (ws->header_used >= 2) {
                int length_code = ws->header[1] & 0x7f;
                needed = 2 + (length_code == 126 ? 2 : length_code == 127 ? 8 : 0) + ((ws->header[1] & 0x80) != 0 ? 4 : 0);
            }
            if (ws->header_used < needed) {
                int received = cz_conn_read(ws->conn, ws->header + ws->header_used, needed - ws->header_used);
                if (received < 0) {
                    ws_fail(ws, 1006, "");
                    break;
                }
                if (received == 0) {
                    return 0;
                }
                ws->header_used += received;
                continue;
            }

            uint8_t opcode = ws->header[0] & 0x0f;
            int length_code = ws->header[1] & 0x7f;
            uint64_t length = (uint64_t)length_code;
            if (length_code == 126) {
                length = ((uint64_t)ws->header[2] << 8) | ws->header[3];
            } else if (length_code == 127) {
                length = 0;
                for (int i = 0; i < 8; i++) {
                    length = (length << 8) | ws->header[2 + i];
                }
            }
            if ((ws->header[1] & 0x80) != 0 || (opcode >= 8 && length > sizeof ws->control)) {
                ws_fail(ws, 1002, "");
                break;
            }
            ws->final = (ws->header[0] & 0x80) != 0;
            ws->opcode = opcode;
            ws->remaining = length;
            ws->control_used = 0;
            ws->header_used = -1; /* header consumed; the payload follows */
            if (opcode == 1 || opcode == 2) {
                ws->message_kind = opcode;
            }
        }

        bool control = ws->opcode >= 8;
        if (ws->remaining > 0) {
            int want = control ? (int)(sizeof ws->control) - ws->control_used : capacity;
            if ((uint64_t)want > ws->remaining) {
                want = (int)ws->remaining;
            }
            int received = cz_conn_read(ws->conn, control ? ws->control + ws->control_used : out, want);
            if (received < 0) {
                ws_fail(ws, 1006, "");
                break;
            }
            if (received == 0) {
                return 0;
            }
            ws->remaining -= (uint64_t)received;
            if (control) {
                ws->control_used += received;
                if (ws->remaining > 0) {
                    continue;
                }
            } else {
                *text = ws->message_kind == 1;
                if (ws->remaining == 0) {
                    ws->header_used = 0;
                    *end = ws->final;
                }
                return received;
            }
        }

        /* A frame is complete (a control frame, or a data frame without payload). */
        ws->header_used = 0;
        if (ws->opcode == 9) {
            ws_send_control(ws, 10, ws->control, (size_t)ws->control_used);
        } else if (ws->opcode == 8) {
            uint16_t code = ws->control_used >= 2 ? (uint16_t)((ws->control[0] << 8) | ws->control[1]) : 1005;
            char reason[sizeof ws->close_reason];
            size_t reason_length = ws->control_used > 2 ? (size_t)ws->control_used - 2 : 0;
            if (reason_length >= sizeof reason) {
                reason_length = sizeof reason - 1;
            }
            memcpy(reason, ws->control + 2, reason_length);
            reason[reason_length] = '\0';
            ws_send_control(ws, 8, ws->control, ws->control_used >= 2 ? 2 : 0);
            ws_fail(ws, code, reason);
            break;
        } else if (!control && ws->final) {
            *text = ws->message_kind == 1;
            *end = true;
            return 0; /* an empty message, or an empty last fragment */
        }
    }
    return -1;
}

bool cz_ws_send(cz_ws *ws, bool text, uint8_t *payload, size_t size)
{
    if (ws->closed || ws->conn == NULL) {
        return false;
    }
    /* The header is written into the headroom in front of the payload, so that header and payload go out in one write. */
    uint8_t mask[4];
    cz_random(mask, sizeof mask);
    size_t header_size = size < 126 ? 6 : size < 65536 ? 8 : 14;
    uint8_t *frame = payload - header_size;
    frame[0] = (uint8_t)(0x80 | (text ? 1 : 2));
    if (size < 126) {
        frame[1] = (uint8_t)(0x80 | size);
    } else if (size < 65536) {
        frame[1] = 0x80 | 126;
        frame[2] = (uint8_t)(size >> 8);
        frame[3] = (uint8_t)size;
    } else {
        frame[1] = 0x80 | 127;
        memset(frame + 2, 0, 4);
        frame[6] = (uint8_t)(size >> 24);
        frame[7] = (uint8_t)(size >> 16);
        frame[8] = (uint8_t)(size >> 8);
        frame[9] = (uint8_t)size;
    }
    memcpy(frame + header_size - 4, mask, 4);
    for (size_t i = 0; i < size; i++) {
        payload[i] ^= mask[i & 3];
    }
    if (!cz_conn_write(ws->conn, frame, header_size + size, IO_TIMEOUT_MS)) {
        ws_fail(ws, 1006, "");
        return false;
    }
    return true;
}

void cz_ws_close(cz_ws *ws, uint16_t code)
{
    if (ws->conn == NULL) {
        return;
    }
    if (!ws->closed) {
        uint8_t payload[2] = { (uint8_t)(code >> 8), (uint8_t)code };
        ws_send_control(ws, 8, payload, sizeof payload);
        ws_fail(ws, code, "");
    }
    cz_conn_close(ws->conn);
    ws->conn = NULL;
}
