/*
 * Session grants (protocol section 2): the control plane's signed statement that one initiator
 * may open one session to this device. The device acts on a grant because its signature checks
 * out, not because of the connection it arrived on. Signatures are ECDSA P-256 over SHA-256
 * (JWS ES256), verified with micro-ecc (vendor/uECC.c).
 */
#include "cz_internal.h"

#include "vendor/uECC.h"

#define CLOCK_SKEW_SECONDS 30
#define MAX_TOKEN_LENGTH 2048

int cz_grant_keys_parse(const char *json, size_t length, cz_grant_key *keys, int capacity)
{
    cz_span document = { json, length };
    cz_span list;
    cz_span jwk;
    size_t cursor = 0;
    int count = 0;
    if (!cz_json_member(document, "keys", &list)) {
        return 0;
    }
    while (count < capacity && cz_json_next(list, &cursor, &jwk)) {
        cz_span value;
        char text[64];
        cz_grant_key *key = &keys[count];
        if (!cz_json_member(jwk, "kty", &value) || !cz_json_string(value, text, sizeof text) || strcmp(text, "EC") != 0) {
            continue;
        }
        if (!cz_json_member(jwk, "crv", &value) || !cz_json_string(value, text, sizeof text) || strcmp(text, "P-256") != 0) {
            continue;
        }
        if (!cz_json_member(jwk, "kid", &value) || !cz_json_string(value, key->kid, sizeof key->kid) || key->kid[0] == '\0') {
            continue;
        }
        if (!cz_json_member(jwk, "x", &value) || !cz_json_string(value, text, sizeof text) || cz_base64_decode(text, strlen(text), key->public_key, 32) != 32) {
            continue;
        }
        if (!cz_json_member(jwk, "y", &value) || !cz_json_string(value, text, sizeof text) || cz_base64_decode(text, strlen(text), key->public_key + 32, 32) != 32) {
            continue;
        }
        /* A point that is not on the curve is not a key. */
        if (uECC_valid_public_key(key->public_key, uECC_secp256r1())) {
            count++;
        }
    }
    return count;
}

bool cz_grant_key_id(const char *token, char *kid, size_t capacity)
{
    const char *dot = token != NULL ? strchr(token, '.') : NULL;
    uint8_t header[128];
    if (dot == NULL || dot == token) {
        return false;
    }
    int length = cz_base64_decode(token, (size_t)(dot - token), header, sizeof header);
    if (length <= 0) {
        return false;
    }
    cz_span object = { (const char *)header, (size_t)length };
    cz_span value;
    return cz_json_member(object, "kid", &value) && cz_json_string(value, kid, capacity) && kid[0] != '\0';
}

static bool read_text(cz_span object, const char *member, char *out, size_t capacity)
{
    cz_span value;
    return cz_json_member(object, member, &value) && cz_json_string(value, out, capacity);
}

const char *cz_grant_verify(const char *token, const cz_grant_key *keys, int key_count, int64_t now, bool for_session_start,
                            uint8_t *scratch, size_t scratch_size, cz_grant *out)
{
    static const char invalid[] = "GRANT_INVALID";
    size_t token_length = token != NULL ? strlen(token) : 0;
    const char *first_dot = token_length > 0 ? strchr(token, '.') : NULL;
    const char *last_dot = token_length > 0 ? strrchr(token, '.') : NULL;
    if (token_length == 0 || token_length > MAX_TOKEN_LENGTH || first_dot == NULL || last_dot == first_dot || first_dot == token || last_dot[1] == '\0'
        || scratch_size < token_length) {
        return invalid;
    }

    /* Header: the algorithm is fixed. Accepting whatever the header names is how "alg" attacks work. */
    int header_length = cz_base64_decode(token, (size_t)(first_dot - token), scratch, scratch_size);
    if (header_length <= 0) {
        return invalid;
    }
    cz_span header = { (const char *)scratch, (size_t)header_length };
    char algorithm[8];
    char kid[24];
    if (!read_text(header, "alg", algorithm, sizeof algorithm) || strcmp(algorithm, "ES256") != 0 || !read_text(header, "kid", kid, sizeof kid)) {
        return invalid;
    }
    const cz_grant_key *key = NULL;
    for (int i = 0; i < key_count; i++) {
        if (strcmp(keys[i].kid, kid) == 0) {
            key = &keys[i];
        }
    }
    if (key == NULL) {
        return invalid;
    }

    /* Signature over "header.payload", exactly as transmitted. */
    uint8_t signature[65];
    uint8_t digest[CZ_SHA256_SIZE];
    if (cz_base64_decode(last_dot + 1, strlen(last_dot + 1), signature, sizeof signature) != 64) {
        return invalid;
    }
    cz_sha256(token, (size_t)(last_dot - token), digest);
    if (!uECC_verify(key->public_key, digest, sizeof digest, signature, uECC_secp256r1())) {
        return invalid;
    }

    int payload_length = cz_base64_decode(first_dot + 1, (size_t)(last_dot - first_dot - 1), scratch, scratch_size);
    if (payload_length <= 0) {
        return invalid;
    }
    cz_span payload = { (const char *)scratch, (size_t)payload_length };
    cz_span value;
    cz_span party;
    memset(out, 0, sizeof *out);

    if (!cz_json_member(payload, "aud", &value) || !cz_json_contains(value, "cz-agent")) {
        return invalid;
    }
    if (!read_text(payload, "jti", out->session_id, sizeof out->session_id) || out->session_id[0] == '\0'
        || !read_text(payload, "ws", out->workspace_id, sizeof out->workspace_id)
        || !cz_json_member(payload, "ini", &party) || !read_text(party, "id", out->initiator_id, sizeof out->initiator_id)
        || !cz_json_member(payload, "dev", &party) || !read_text(party, "id", out->device_id, sizeof out->device_id)
        || !cz_json_member(payload, "iat", &value) || !cz_json_int(value, &out->issued_at)
        || !cz_json_member(payload, "exp", &value) || !cz_json_int(value, &out->expires_at)
        || !cz_json_member(payload, "lease", &value) || !cz_json_int(value, &out->lease_seconds)) {
        return invalid;
    }

    if (cz_json_member(payload, "svc", &value)) {
        size_t cursor = 0;
        cz_span name;
        while (out->service_count < CZ_MAX_GRANT_SERVICES && cz_json_next(value, &cursor, &name)) {
            if (cz_json_string(name, out->services[out->service_count], CZ_NAME_SIZE)) {
                out->service_count++;
            }
        }
    }
    if (cz_json_member(payload, "modes", &value)) {
        out->mode_direct = cz_json_contains(value, "direct");
        out->mode_relay = cz_json_contains(value, "e2e-relay");
        out->mode_compatibility = cz_json_contains(value, "compatibility");
    }
    char layer[16] = "";
    if (cz_json_member(payload, "e2e", &value)) {
        cz_json_string(value, layer, sizeof layer);
    }
    out->shared_key = strcmp(layer, "shared-key") == 0;
    if (cz_json_member(payload, "relay", &value) && !cz_json_string(value, out->relay_url, sizeof out->relay_url)) {
        out->relay_url[0] = '\0';
    }

    int64_t deadline = for_session_start ? out->expires_at : out->issued_at + out->lease_seconds;
    if (now > deadline + CLOCK_SKEW_SECONDS || now < out->issued_at - CLOCK_SKEW_SECONDS) {
        return "GRANT_EXPIRED";
    }
    return NULL;
}
