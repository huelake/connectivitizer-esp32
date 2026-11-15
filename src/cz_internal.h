/* Declarations shared by the modules of the library. Not part of the public interface. */
#ifndef CZ_INTERNAL_H
#define CZ_INTERNAL_H

#include "cz.h"
#include "port/cz_port.h"

#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- cz_util.c: encodings and hashes ---------------------------------------------------- */

#define CZ_SHA256_SIZE 32

typedef struct {
    uint32_t state[8];
    uint64_t length;
    uint8_t block[64];
    size_t used;
} cz_sha256_ctx;

void cz_sha256_init(cz_sha256_ctx *ctx);
void cz_sha256_update(cz_sha256_ctx *ctx, const void *data, size_t size);
void cz_sha256_final(cz_sha256_ctx *ctx, uint8_t out[CZ_SHA256_SIZE]);
void cz_sha256(const void *data, size_t size, uint8_t out[CZ_SHA256_SIZE]);
void cz_hmac_sha256(const uint8_t *key, size_t key_size, const void *data, size_t size, uint8_t out[CZ_SHA256_SIZE]);

/* Lower-case hex; out must hold 2 * size + 1 characters. */
void cz_hex(const uint8_t *data, size_t size, char *out);

/* Decodes base64 and base64url, with or without padding. Returns the length, or -1. */
int cz_base64_decode(const char *text, size_t length, uint8_t *out, size_t capacity);

/* Standard base64 with padding. Returns the length written (without the terminator), or -1. */
int cz_base64_encode(const uint8_t *data, size_t size, char *out, size_t capacity);

/* True when equal; the time taken does not depend on where the inputs differ. */
bool cz_equal(const uint8_t *a, const uint8_t *b, size_t size);

/* Copies at most capacity - 1 characters and always terminates. */
void cz_copy(char *out, size_t capacity, const char *text);

/* ---- cz_json.c: reading JSON without allocating ------------------------------------------ */

typedef struct {
    const char *at;
    size_t length;
} cz_span;

/* The value of member `key` of the object `object`. False when absent or `object` is not an object. */
bool cz_json_member(cz_span object, const char *key, cz_span *value);

/* The next element of `array`; start with *cursor = 0. False at the end. */
bool cz_json_next(cz_span array, size_t *cursor, cz_span *element);

/* Copies a string value, resolving escapes. False when it is not a string or does not fit. */
bool cz_json_string(cz_span value, char *out, size_t capacity);

bool cz_json_int(cz_span value, int64_t *out);
bool cz_json_bool(cz_span value, bool *out);

/* True when `array` is an array that contains the string `text`. */
bool cz_json_contains(cz_span array, const char *text);

/* Writes `text` as a JSON string, quotes included. Returns the characters written, or -1 if it does not fit. */
int cz_json_quote(char *out, size_t capacity, const char *text);

/* ---- cz_noise.c: the shared-key handshake and its transport (protocol section 4a) -------- */

#define CZ_KEY_SIZE 32
#define CZ_TAG_SIZE 16
#define CZ_HANDSHAKE_SIZE (CZ_KEY_SIZE + CZ_TAG_SIZE)
#define CZ_MAX_PLAINTEXT 4096

typedef struct {
    uint8_t chaining_key[32];
    uint8_t hash[32];
    uint8_t key[32];
    uint64_t counter;
    uint8_t ephemeral[32];
    uint8_t remote_public[32];
} cz_noise_handshake;

typedef struct {
    uint8_t send_key[32];
    uint8_t receive_key[32];
    uint64_t send_counter;
    uint64_t receive_counter;
} cz_noise_transport;

/* Parses "czs_..." into 32 bytes. */
bool cz_shared_key_parse(const char *text, uint8_t key[CZ_KEY_SIZE]);

/*
 * The responder's side. Processes the initiator's message with one candidate key; false when the
 * message was not made with that key. The payload (payload_size = message size - 48 bytes) is
 * written to `payload` if that is not NULL.
 */
bool cz_noise_respond_begin(cz_noise_handshake *hs, const uint8_t *prologue, size_t prologue_size, const uint8_t key[CZ_KEY_SIZE],
                            const uint8_t *message, size_t message_size, uint8_t *payload);

/* Writes the responder's message (32 + payload_size + 16 bytes) and derives the transport keys. False on an invalid key-agreement value. */
bool cz_noise_respond_finish(cz_noise_handshake *hs, const uint8_t ephemeral_private[CZ_KEY_SIZE], const uint8_t *payload, size_t payload_size,
                             uint8_t *message, cz_noise_transport *transport);

/* The initiator's side, used by the tests: writes the first message (32 + payload_size + 16 bytes). */
void cz_noise_initiate(cz_noise_handshake *hs, const uint8_t *prologue, size_t prologue_size, const uint8_t key[CZ_KEY_SIZE],
                       const uint8_t ephemeral_private[CZ_KEY_SIZE], const uint8_t *payload, size_t payload_size, uint8_t *message);

/* The initiator reads the responder's message. False when it was not made with the same key. */
bool cz_noise_initiate_finish(cz_noise_handshake *hs, const uint8_t *message, size_t message_size, uint8_t *payload, cz_noise_transport *transport);

/* Encrypts in place: `data` holds `size` plaintext bytes and room for the 16-byte tag after them. */
void cz_noise_encrypt(cz_noise_transport *transport, uint8_t *data, size_t size);

/* Decrypts in place: `data` holds `size` bytes including the tag. False when the message was altered. */
bool cz_noise_decrypt(cz_noise_transport *transport, uint8_t *data, size_t size);

/* ---- cz_grant.c: session grants (protocol section 2) -------------------------------------- */

#define CZ_MAX_GRANT_KEYS 3
#define CZ_MAX_GRANT_SERVICES 8
#define CZ_NAME_SIZE 61
#define CZ_ID_SIZE 40

typedef struct {
    char kid[24];
    uint8_t public_key[64]; /* x || y */
} cz_grant_key;

typedef struct {
    char session_id[CZ_ID_SIZE];
    char workspace_id[CZ_ID_SIZE];
    char initiator_id[CZ_ID_SIZE];
    char device_id[CZ_ID_SIZE];
    char services[CZ_MAX_GRANT_SERVICES][CZ_NAME_SIZE];
    int service_count;
    bool mode_direct;
    bool mode_relay;
    bool mode_compatibility;
    bool shared_key; /* the session's end-to-end layer is the shared-key one */
    char relay_url[200];
    int64_t issued_at;
    int64_t expires_at;
    int64_t lease_seconds;
} cz_grant;

/* Reads the keys of a JWKS document. Returns how many were stored. */
int cz_grant_keys_parse(const char *json, size_t length, cz_grant_key *keys, int capacity);

/* The key id a token names; false when the token has none. */
bool cz_grant_key_id(const char *token, char *kid, size_t capacity);

/*
 * Verifies signature, audience and time of a grant token and reads it. `scratch` is working
 * memory of at least the token's length. Returns NULL on success, otherwise the error code.
 */
const char *cz_grant_verify(const char *token, const cz_grant_key *keys, int key_count, int64_t now, bool for_session_start,
                            uint8_t *scratch, size_t scratch_size, cz_grant *out);

/* ---- cz_net.c: URLs, HTTP and WebSocket over a connection --------------------------------- */

typedef struct {
    bool secure;
    char host[100];
    uint16_t port;
    char path[160]; /* starts with '/', no trailing '/' unless it is the root */
} cz_url;

bool cz_url_parse(const char *text, cz_url *out);

/*
 * One HTTP request. `body` may be NULL (then it is a GET). The response body is written to
 * `response` and terminated; returns the HTTP status, or -1 when the server could not be reached.
 * If server_time is not NULL it receives the Date header as Unix time, or 0.
 */
int cz_http_request(const cz_url *url, const char *path_suffix, const char *body, const char *root_ca, char *response, size_t capacity);

typedef struct {
    cz_conn *conn;
    uint8_t header[14];
    int header_used;
    uint64_t remaining;   /* payload bytes of the current frame still to come */
    uint8_t opcode;       /* of the current frame */
    uint8_t message_kind; /* 1 text, 2 binary: what the current message is */
    bool final;
    bool closed;
    uint16_t close_code;
    char close_reason[40];
    uint8_t control[128]; /* payload of a control frame */
    int control_used;
} cz_ws;

/*
 * Opens a WebSocket. `headers` are complete header lines ("Name: value\r\n...") or NULL. On a
 * refusal `error` receives the code the server named (header Cz-Error) or a generic one.
 */
bool cz_ws_open(cz_ws *ws, const char *url, const char *headers, const char *root_ca, char *error, size_t error_capacity);

/* For select(): the socket, and whether data is waiting that select would not show. */
int cz_ws_fd(const cz_ws *ws);
bool cz_ws_pending(cz_ws *ws);

/*
 * Reads payload bytes of the current message without waiting. Returns the number of bytes, 0 when
 * nothing is available right now, -1 when the connection is closed (see close_code, close_reason).
 * *text says whether they belong to a text message, *end whether the message is complete with them.
 */
int cz_ws_read(cz_ws *ws, uint8_t *out, int capacity, bool *text, bool *end);

/* Headroom a caller leaves in front of the payload it hands to cz_ws_send. */
#define CZ_WS_HEADROOM 14

/* Sends one message. The payload is masked in place, and the bytes before it are used for the frame header. */
bool cz_ws_send(cz_ws *ws, bool text, uint8_t *payload, size_t size);

/* Sends a close frame and closes the connection. */
void cz_ws_close(cz_ws *ws, uint16_t code);

#ifdef __cplusplus
}
#endif

#endif
