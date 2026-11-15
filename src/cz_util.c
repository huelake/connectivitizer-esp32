/* Encodings and SHA-256. Small, without dependencies, the same on every chip. */
#include "cz_internal.h"

/* ---- SHA-256 (FIPS 180-4) ----------------------------------------------------------------- */

static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be,
    0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa,
    0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85,
    0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f,
    0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

#define ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

static void sha256_block(cz_sha256_ctx *ctx, const uint8_t *block)
{
    uint32_t w[64];
    for (int i = 0; i < 16; i++) {
        w[i] = ((uint32_t)block[4 * i] << 24) | ((uint32_t)block[4 * i + 1] << 16) | ((uint32_t)block[4 * i + 2] << 8) | block[4 * i + 3];
    }
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = ROTR(w[i - 15], 7) ^ ROTR(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = ROTR(w[i - 2], 17) ^ ROTR(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    uint32_t a = ctx->state[0], b = ctx->state[1], c = ctx->state[2], d = ctx->state[3];
    uint32_t e = ctx->state[4], f = ctx->state[5], g = ctx->state[6], h = ctx->state[7];
    for (int i = 0; i < 64; i++) {
        uint32_t s1 = ROTR(e, 6) ^ ROTR(e, 11) ^ ROTR(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t t1 = h + s1 + ch + K[i] + w[i];
        uint32_t s0 = ROTR(a, 2) ^ ROTR(a, 13) ^ ROTR(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = s0 + maj;
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }
    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;
}

void cz_sha256_init(cz_sha256_ctx *ctx)
{
    static const uint32_t initial[8] = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };
    memcpy(ctx->state, initial, sizeof initial);
    ctx->length = 0;
    ctx->used = 0;
}

void cz_sha256_update(cz_sha256_ctx *ctx, const void *data, size_t size)
{
    const uint8_t *bytes = (const uint8_t *)data;
    ctx->length += size;
    while (size > 0) {
        size_t take = 64 - ctx->used;
        if (take > size) {
            take = size;
        }
        memcpy(ctx->block + ctx->used, bytes, take);
        ctx->used += take;
        bytes += take;
        size -= take;
        if (ctx->used == 64) {
            sha256_block(ctx, ctx->block);
            ctx->used = 0;
        }
    }
}

void cz_sha256_final(cz_sha256_ctx *ctx, uint8_t out[CZ_SHA256_SIZE])
{
    uint64_t bits = ctx->length * 8;
    uint8_t pad = 0x80;
    cz_sha256_update(ctx, &pad, 1);
    pad = 0;
    while (ctx->used != 56) {
        cz_sha256_update(ctx, &pad, 1);
    }
    uint8_t length[8];
    for (int i = 0; i < 8; i++) {
        length[i] = (uint8_t)(bits >> (56 - 8 * i));
    }
    cz_sha256_update(ctx, length, 8);
    for (int i = 0; i < 8; i++) {
        out[4 * i] = (uint8_t)(ctx->state[i] >> 24);
        out[4 * i + 1] = (uint8_t)(ctx->state[i] >> 16);
        out[4 * i + 2] = (uint8_t)(ctx->state[i] >> 8);
        out[4 * i + 3] = (uint8_t)ctx->state[i];
    }
}

void cz_sha256(const void *data, size_t size, uint8_t out[CZ_SHA256_SIZE])
{
    cz_sha256_ctx ctx;
    cz_sha256_init(&ctx);
    cz_sha256_update(&ctx, data, size);
    cz_sha256_final(&ctx, out);
}

/* HMAC (RFC 2104) with SHA-256. */
void cz_hmac_sha256(const uint8_t *key, size_t key_size, const void *data, size_t size, uint8_t out[CZ_SHA256_SIZE])
{
    uint8_t block[64];
    uint8_t inner[CZ_SHA256_SIZE];
    memset(block, 0, sizeof block);
    if (key_size > sizeof block) {
        cz_sha256(key, key_size, block);
    } else {
        memcpy(block, key, key_size);
    }

    cz_sha256_ctx ctx;
    for (size_t i = 0; i < sizeof block; i++) {
        block[i] ^= 0x36;
    }
    cz_sha256_init(&ctx);
    cz_sha256_update(&ctx, block, sizeof block);
    cz_sha256_update(&ctx, data, size);
    cz_sha256_final(&ctx, inner);

    for (size_t i = 0; i < sizeof block; i++) {
        block[i] ^= 0x36 ^ 0x5c;
    }
    cz_sha256_init(&ctx);
    cz_sha256_update(&ctx, block, sizeof block);
    cz_sha256_update(&ctx, inner, sizeof inner);
    cz_sha256_final(&ctx, out);
}

/* ---- Encodings ---------------------------------------------------------------------------- */

void cz_hex(const uint8_t *data, size_t size, char *out)
{
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < size; i++) {
        out[2 * i] = digits[data[i] >> 4];
        out[2 * i + 1] = digits[data[i] & 15];
    }
    out[2 * size] = '\0';
}

static int base64_value(char c)
{
    if (c >= 'A' && c <= 'Z') {
        return c - 'A';
    }
    if (c >= 'a' && c <= 'z') {
        return c - 'a' + 26;
    }
    if (c >= '0' && c <= '9') {
        return c - '0' + 52;
    }
    if (c == '+' || c == '-') {
        return 62;
    }
    if (c == '/' || c == '_') {
        return 63;
    }
    return -1;
}

int cz_base64_decode(const char *text, size_t length, uint8_t *out, size_t capacity)
{
    while (length > 0 && text[length - 1] == '=') {
        length--;
    }
    if (length % 4 == 1) {
        return -1;
    }
    uint32_t bits = 0;
    int count = 0;
    size_t written = 0;
    for (size_t i = 0; i < length; i++) {
        int value = base64_value(text[i]);
        if (value < 0) {
            return -1;
        }
        bits = (bits << 6) | (uint32_t)value;
        count += 6;
        if (count >= 8) {
            count -= 8;
            if (written >= capacity) {
                return -1;
            }
            out[written++] = (uint8_t)(bits >> count);
        }
    }
    return (int)written;
}

int cz_base64_encode(const uint8_t *data, size_t size, char *out, size_t capacity)
{
    static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t needed = ((size + 2) / 3) * 4;
    if (needed + 1 > capacity) {
        return -1;
    }
    size_t written = 0;
    for (size_t i = 0; i < size; i += 3) {
        uint32_t a = data[i];
        uint32_t b = i + 1 < size ? data[i + 1] : 0;
        uint32_t c = i + 2 < size ? data[i + 2] : 0;
        out[written++] = alphabet[a >> 2];
        out[written++] = alphabet[((a & 3) << 4) | (b >> 4)];
        out[written++] = i + 1 < size ? alphabet[((b & 15) << 2) | (c >> 6)] : '=';
        out[written++] = i + 2 < size ? alphabet[c & 63] : '=';
    }
    out[written] = '\0';
    return (int)written;
}

bool cz_equal(const uint8_t *a, const uint8_t *b, size_t size)
{
    uint8_t difference = 0;
    for (size_t i = 0; i < size; i++) {
        difference |= (uint8_t)(a[i] ^ b[i]);
    }
    return difference == 0;
}

void cz_copy(char *out, size_t capacity, const char *text)
{
    if (capacity == 0) {
        return;
    }
    size_t length = text != NULL ? strlen(text) : 0;
    if (length >= capacity) {
        length = capacity - 1;
    }
    if (length > 0) {
        memcpy(out, text, length);
    }
    out[length] = '\0';
}
