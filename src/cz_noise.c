/*
 * The end-to-end layer for endpoints that share a key (protocol section 4a): the Noise handshake
 * NNpsk0 with X25519, ChaCha20-Poly1305 and SHA-256, as revision 34 of the Noise specification
 * defines it.
 *
 *     initiator -> device :  psk, e
 *     device -> initiator :  e, ee
 *
 * X25519 and ChaCha20-Poly1305 come from Monocypher (vendor/monocypher.c), SHA-256 from cz_util.c.
 * The code is checked against the published test vector for this protocol name.
 */
#include "cz_internal.h"

#include "vendor/monocypher.h"

static const char protocol_name[] = "Noise_NNpsk0_25519_ChaChaPoly_SHA256";

bool cz_shared_key_parse(const char *text, uint8_t key[CZ_KEY_SIZE])
{
    uint8_t decoded[CZ_KEY_SIZE + 1];
    if (text == NULL || strncmp(text, "czs_", 4) != 0 || strlen(text) != 4 + 43) {
        return false;
    }
    if (cz_base64_decode(text + 4, 43, decoded, sizeof decoded) != CZ_KEY_SIZE) {
        return false;
    }
    memcpy(key, decoded, CZ_KEY_SIZE);
    crypto_wipe(decoded, sizeof decoded);
    return true;
}

/* ChaCha20-Poly1305 with the nonce Noise prescribes: four zero bytes, then the counter, little-endian. */
static void make_nonce(uint8_t nonce[12], uint64_t counter)
{
    memset(nonce, 0, 4);
    for (int i = 0; i < 8; i++) {
        nonce[4 + i] = (uint8_t)(counter >> (8 * i));
    }
}

/* Encrypts in place and writes the tag behind the text. */
static void aead_encrypt(const uint8_t key[32], uint64_t counter, const uint8_t *ad, size_t ad_size, uint8_t *data, size_t size)
{
    uint8_t nonce[12];
    crypto_aead_ctx ctx;
    make_nonce(nonce, counter);
    crypto_aead_init_ietf(&ctx, key, nonce);
    crypto_aead_write(&ctx, data, data + size, ad, ad_size, data, size);
    crypto_wipe(&ctx, sizeof ctx);
}

/* Decrypts in place; `size` is the length without the tag, which follows the text. */
static bool aead_decrypt(const uint8_t key[32], uint64_t counter, const uint8_t *ad, size_t ad_size, uint8_t *data, size_t size)
{
    uint8_t nonce[12];
    crypto_aead_ctx ctx;
    make_nonce(nonce, counter);
    crypto_aead_init_ietf(&ctx, key, nonce);
    int result = crypto_aead_read(&ctx, data, data + size, ad, ad_size, data, size);
    crypto_wipe(&ctx, sizeof ctx);
    return result == 0;
}

static void mix_hash(cz_noise_handshake *hs, const uint8_t *data, size_t size)
{
    cz_sha256_ctx ctx;
    cz_sha256_init(&ctx);
    cz_sha256_update(&ctx, hs->hash, 32);
    cz_sha256_update(&ctx, data, size);
    cz_sha256_final(&ctx, hs->hash);
}

/* One output block of the HKDF that Noise defines: HMAC(key, previous block || counter). */
static void expand(const uint8_t temp[32], const uint8_t *previous, size_t previous_size, uint8_t counter, uint8_t out[32])
{
    uint8_t input[33];
    if (previous_size > 0) {
        memcpy(input, previous, previous_size);
    }
    input[previous_size] = counter;
    cz_hmac_sha256(temp, 32, input, previous_size + 1, out);
}

static void mix_key(cz_noise_handshake *hs, const uint8_t *material, size_t size)
{
    uint8_t temp[32];
    uint8_t first[32];
    cz_hmac_sha256(hs->chaining_key, 32, material, size, temp);
    expand(temp, NULL, 0, 1, first);
    expand(temp, first, 32, 2, hs->key);
    memcpy(hs->chaining_key, first, 32);
    hs->counter = 0;
    crypto_wipe(temp, sizeof temp);
}

static void mix_key_and_hash(cz_noise_handshake *hs, const uint8_t *material, size_t size)
{
    uint8_t temp[32];
    uint8_t first[32];
    uint8_t second[32];
    cz_hmac_sha256(hs->chaining_key, 32, material, size, temp);
    expand(temp, NULL, 0, 1, first);
    expand(temp, first, 32, 2, second);
    expand(temp, second, 32, 3, hs->key);
    memcpy(hs->chaining_key, first, 32);
    mix_hash(hs, second, 32);
    hs->counter = 0;
    crypto_wipe(temp, sizeof temp);
}

static void begin(cz_noise_handshake *hs, const uint8_t *prologue, size_t prologue_size, const uint8_t key[CZ_KEY_SIZE])
{
    /* The protocol name is longer than a hash, so the initial hash is the hash of the name. */
    cz_sha256(protocol_name, sizeof protocol_name - 1, hs->hash);
    memcpy(hs->chaining_key, hs->hash, 32);
    mix_hash(hs, prologue, prologue_size);
    mix_key_and_hash(hs, key, CZ_KEY_SIZE);
}

/* Writes `size` plaintext bytes at `out` encrypted, followed by the tag, and mixes both into the hash. */
static void encrypt_and_hash(cz_noise_handshake *hs, const uint8_t *plaintext, size_t size, uint8_t *out)
{
    if (size > 0) {
        memmove(out, plaintext, size);
    }
    aead_encrypt(hs->key, hs->counter++, hs->hash, 32, out, size);
    mix_hash(hs, out, size + CZ_TAG_SIZE);
}

/* `ciphertext` holds `size` bytes including the tag. The plaintext goes to `out` when that is not NULL. */
static bool decrypt_and_hash(cz_noise_handshake *hs, const uint8_t *ciphertext, size_t size, uint8_t *out)
{
    uint8_t buffer[64 + CZ_TAG_SIZE];
    uint8_t previous_hash[32];
    if (size < CZ_TAG_SIZE || size > sizeof buffer) {
        return false; /* handshake payloads in this protocol are empty; 64 bytes is ample */
    }
    memcpy(buffer, ciphertext, size);
    memcpy(previous_hash, hs->hash, 32);
    if (!aead_decrypt(hs->key, hs->counter++, previous_hash, 32, buffer, size - CZ_TAG_SIZE)) {
        return false;
    }
    mix_hash(hs, ciphertext, size);
    if (out != NULL && size > CZ_TAG_SIZE) {
        memcpy(out, buffer, size - CZ_TAG_SIZE);
    }
    return true;
}

/* X25519; false when the peer sent a point of small order, which forces a known result. */
static bool agree(const uint8_t private_key[32], const uint8_t remote_public[32], uint8_t shared[32])
{
    static const uint8_t zero[32] = { 0 };
    crypto_x25519(shared, private_key, remote_public);
    return !cz_equal(shared, zero, 32);
}

static void split(const cz_noise_handshake *hs, uint8_t initiator_key[32], uint8_t responder_key[32])
{
    uint8_t temp[32];
    cz_hmac_sha256(hs->chaining_key, 32, NULL, 0, temp);
    expand(temp, NULL, 0, 1, initiator_key);
    expand(temp, initiator_key, 32, 2, responder_key);
    crypto_wipe(temp, sizeof temp);
}

bool cz_noise_respond_begin(cz_noise_handshake *hs, const uint8_t *prologue, size_t prologue_size, const uint8_t key[CZ_KEY_SIZE],
                            const uint8_t *message, size_t message_size, uint8_t *payload)
{
    if (message_size < CZ_HANDSHAKE_SIZE) {
        return false;
    }
    begin(hs, prologue, prologue_size, key);
    memcpy(hs->remote_public, message, CZ_KEY_SIZE);
    mix_hash(hs, hs->remote_public, CZ_KEY_SIZE);
    mix_key(hs, hs->remote_public, CZ_KEY_SIZE);
    return decrypt_and_hash(hs, message + CZ_KEY_SIZE, message_size - CZ_KEY_SIZE, payload);
}

bool cz_noise_respond_finish(cz_noise_handshake *hs, const uint8_t ephemeral_private[CZ_KEY_SIZE], const uint8_t *payload, size_t payload_size,
                             uint8_t *message, cz_noise_transport *transport)
{
    uint8_t shared[32];
    crypto_x25519_public_key(message, ephemeral_private);
    mix_hash(hs, message, CZ_KEY_SIZE);
    mix_key(hs, message, CZ_KEY_SIZE);
    if (!agree(ephemeral_private, hs->remote_public, shared)) {
        return false;
    }
    mix_key(hs, shared, 32);
    crypto_wipe(shared, sizeof shared);
    encrypt_and_hash(hs, payload, payload_size, message + CZ_KEY_SIZE);

    /* The first key protects what the initiator sends, the second what the responder sends. */
    split(hs, transport->receive_key, transport->send_key);
    transport->send_counter = 0;
    transport->receive_counter = 0;
    crypto_wipe(hs, sizeof *hs);
    return true;
}

void cz_noise_initiate(cz_noise_handshake *hs, const uint8_t *prologue, size_t prologue_size, const uint8_t key[CZ_KEY_SIZE],
                       const uint8_t ephemeral_private[CZ_KEY_SIZE], const uint8_t *payload, size_t payload_size, uint8_t *message)
{
    begin(hs, prologue, prologue_size, key);
    memcpy(hs->ephemeral, ephemeral_private, CZ_KEY_SIZE);
    crypto_x25519_public_key(message, ephemeral_private);
    mix_hash(hs, message, CZ_KEY_SIZE);
    mix_key(hs, message, CZ_KEY_SIZE);
    encrypt_and_hash(hs, payload, payload_size, message + CZ_KEY_SIZE);
}

bool cz_noise_initiate_finish(cz_noise_handshake *hs, const uint8_t *message, size_t message_size, uint8_t *payload, cz_noise_transport *transport)
{
    uint8_t shared[32];
    if (message_size < CZ_HANDSHAKE_SIZE) {
        return false;
    }
    mix_hash(hs, message, CZ_KEY_SIZE);
    mix_key(hs, message, CZ_KEY_SIZE);
    if (!agree(hs->ephemeral, message, shared)) {
        return false;
    }
    mix_key(hs, shared, 32);
    crypto_wipe(shared, sizeof shared);
    if (!decrypt_and_hash(hs, message + CZ_KEY_SIZE, message_size - CZ_KEY_SIZE, payload)) {
        return false;
    }
    split(hs, transport->send_key, transport->receive_key);
    transport->send_counter = 0;
    transport->receive_counter = 0;
    crypto_wipe(hs, sizeof *hs);
    return true;
}

void cz_noise_encrypt(cz_noise_transport *transport, uint8_t *data, size_t size)
{
    aead_encrypt(transport->send_key, transport->send_counter++, NULL, 0, data, size);
}

bool cz_noise_decrypt(cz_noise_transport *transport, uint8_t *data, size_t size)
{
    if (size < CZ_TAG_SIZE) {
        return false;
    }
    return aead_decrypt(transport->receive_key, transport->receive_counter++, NULL, 0, data, size - CZ_TAG_SIZE);
}
