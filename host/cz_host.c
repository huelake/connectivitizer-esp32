/*
 * The library on a PC: the same code that runs on the chip, as a program driven by its
 * environment. It is what the interoperability tests run against the other SDKs, and a way to
 * try the device side without hardware.
 *
 *   cz_host selftest          check the cryptography against published test vectors
 *   cz_host                   run a device:
 *     CZ_API_URL, CZ_DEVICE_KEY, CZ_DEVICE_NAME, CZ_SHARED_KEY
 *     CZ_TARGET               host:port of the local application to expose as CZ_SERVICE (default api)
 *     CZ_DIRECT=none          never attempt a peer-to-peer connection
 *     CZ_LOOPBACK=true        offer 127.0.0.1 (both endpoints on one machine)
 *
 * It prints READY once the platform sees the device, and its log after that. A line on stdin, or
 * stdin closing, stops it.
 */
#include "../src/cz_internal.h"

#include <stdio.h>
#include <stdlib.h>

#if defined(_WIN32)
#include <process.h>
#else
#include <pthread.h>
#endif

static void log_line(const char *line, void *user)
{
    (void)user;
    printf("%s\n", line);
    fflush(stdout);
}

static cz_agent *running;

#if defined(_WIN32)
static unsigned __stdcall watch_stdin(void *argument)
#else
static void *watch_stdin(void *argument)
#endif
{
    (void)argument;
    (void)getchar(); /* returns on a line and when stdin closes */
    if (running != NULL) {
        cz_agent_stop(running);
    }
    return 0;
}

/* ---- Self test ---------------------------------------------------------------------------- */

static int failures;

static void from_hex(const char *hex, uint8_t *out)
{
    for (size_t i = 0; hex[2 * i] != '\0'; i++) {
        unsigned value;
        sscanf(hex + 2 * i, "%2x", &value);
        out[i] = (uint8_t)value;
    }
}

static void expect_hex(const char *what, const uint8_t *actual, size_t size, const char *expected)
{
    char text[400];
    cz_hex(actual, size, text);
    if (strcmp(text, expected) != 0) {
        printf("FAIL %s\n  expected %s\n  actual   %s\n", what, expected, text);
        failures++;
    } else {
        printf("ok   %s\n", what);
    }
}

static void expect(const char *what, bool condition)
{
    printf("%s %s\n", condition ? "ok  " : "FAIL", what);
    if (!condition) {
        failures++;
    }
}

static int selftest(void)
{
    uint8_t digest[32];

    /* SHA-256 and HMAC: FIPS 180-4 and RFC 4231. */
    cz_sha256("abc", 3, digest);
    expect_hex("sha256(abc)", digest, 32, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    cz_sha256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56, digest);
    expect_hex("sha256(two blocks)", digest, 32, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
    uint8_t hmac_key[20];
    memset(hmac_key, 0x0b, sizeof hmac_key);
    cz_hmac_sha256(hmac_key, sizeof hmac_key, "Hi There", 8, digest);
    expect_hex("hmac-sha256 (RFC 4231 case 1)", digest, 32, "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");

    /* The published vector for Noise_NNpsk0_25519_ChaChaPoly_SHA256 (cacophony): the same one the
       .NET and the TypeScript implementation are checked against. */
    uint8_t prologue[9], key[32], initiator_private[32], responder_private[32], payload1[16], payload2[15];
    from_hex("4a6f686e2047616c74", prologue);
    from_hex("54686973206973206d7920417573747269616e20706572737065637469766521", key);
    from_hex("893e28b9dc6ca8d611ab664754b8ceb7bac5117349a4439a6b0569da977c464a", initiator_private);
    from_hex("bbdb4cdbd309f1a1f2e1456967fe288cadd6f712d65dc7b7793d5e63da6b375b", responder_private);
    from_hex("4c756477696720766f6e204d69736573", payload1);
    from_hex("4d757272617920526f746862617264", payload2);

    cz_noise_handshake initiator, responder;
    cz_noise_transport initiator_keys, responder_keys;
    uint8_t message1[32 + 16 + 16], message2[32 + 15 + 16], received[64];
    cz_noise_initiate(&initiator, prologue, sizeof prologue, key, initiator_private, payload1, sizeof payload1, message1);
    expect_hex("noise message 1", message1, sizeof message1,
               "ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c794479b962b8aff8485742ac32f905ba45369e2465fb59e138a93d67a0d1266b6a54");

    uint8_t wrong_key[32];
    memset(wrong_key, 7, sizeof wrong_key);
    expect("noise: another key is refused", !cz_noise_respond_begin(&responder, prologue, sizeof prologue, wrong_key, message1, sizeof message1, received));
    expect("noise: another prologue is refused", !cz_noise_respond_begin(&responder, prologue, sizeof prologue - 1, key, message1, sizeof message1, received));
    expect("noise: the right key is accepted", cz_noise_respond_begin(&responder, prologue, sizeof prologue, key, message1, sizeof message1, received));
    expect("noise: payload 1 arrives", memcmp(received, payload1, sizeof payload1) == 0);
    expect("noise: responder finishes", cz_noise_respond_finish(&responder, responder_private, payload2, sizeof payload2, message2, &responder_keys));
    expect_hex("noise message 2", message2, sizeof message2,
               "95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f144808843d6062704d5a9c422a8e834423f8c1feada7e8d0d910a1a2cd030fb584221e3");
    expect("noise: initiator finishes", cz_noise_initiate_finish(&initiator, message2, sizeof message2, received, &initiator_keys));
    expect("noise: payload 2 arrives", memcmp(received, payload2, sizeof payload2) == 0);

    /* The transport messages of the vector: each direction counts its own messages from zero. */
    uint8_t buffer[64];
    from_hex("462e20412e20486179656b", buffer);
    cz_noise_encrypt(&initiator_keys, buffer, 11);
    expect_hex("noise transport 1", buffer, 11 + 16, "e632c3763d7669067383433197a3baddf146e9e70ad4b4e9e59e0f");
    expect("noise: the device decrypts it", cz_noise_decrypt(&responder_keys, buffer, 11 + 16) && memcmp(buffer, "F. A. Hayek", 11) == 0);
    from_hex("4361726c204d656e676572", buffer);
    cz_noise_encrypt(&responder_keys, buffer, 11);
    expect_hex("noise transport 2", buffer, 11 + 16, "64c6bee32ea91c8474bb4c21d7a700109ad45af77b29764ba5eb1e");
    buffer[3] ^= 1;
    expect("noise: an altered message is refused", !cz_noise_decrypt(&initiator_keys, buffer, 11 + 16));

    /* Encodings and JSON. */
    uint8_t decoded[40];
    expect("base64url decode", cz_base64_decode("aGVsbG8gd29ybGQ", 15, decoded, sizeof decoded) == 11 && memcmp(decoded, "hello world", 11) == 0);
    expect("base64 decode with padding", cz_base64_decode("aGVsbG8=", 8, decoded, sizeof decoded) == 5);
    expect("base64 refuses other text", cz_base64_decode("not base64!", 11, decoded, sizeof decoded) < 0);
    char encoded[40];
    expect("base64 encode", cz_base64_encode((const uint8_t *)"hello", 5, encoded, sizeof encoded) == 8 && strcmp(encoded, "aGVsbG8=") == 0);
    uint8_t shared[32];
    expect("shared key: text form", cz_shared_key_parse("czs_AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8", shared) && shared[31] == 31);
    expect("shared key: another prefix is refused", !cz_shared_key_parse("czk_AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8", shared));

    const char *json = "{\"t\":\"connect.offer\",\"d\":{\"sid\":\"abc\",\"n\":-12,\"ok\":true,\"peer\":{\"name\":\"Example \\\"app\\\" \\u00e4\",\"caps\":[\"a\",\"path.udp-kcp\"]},\"empty\":[]}}";
    cz_span document = { json, strlen(json) };
    cz_span data, value, peer;
    char text[64];
    int64_t number = 0;
    bool flag = false;
    expect("json: nested members", cz_json_member(document, "d", &data) && cz_json_member(data, "peer", &peer)
                                       && cz_json_member(peer, "name", &value) && cz_json_string(value, text, sizeof text) && strcmp(text, "Example \"app\" \xc3\xa4") == 0);
    expect("json: numbers and booleans", cz_json_member(data, "n", &value) && cz_json_int(value, &number) && number == -12
                                             && cz_json_member(data, "ok", &value) && cz_json_bool(value, &flag) && flag);
    expect("json: arrays", cz_json_member(peer, "caps", &value) && cz_json_contains(value, "path.udp-kcp") && !cz_json_contains(value, "path.tcp")
                               && cz_json_member(data, "empty", &value) && !cz_json_contains(value, "a"));
    expect("json: absent members and broken text", !cz_json_member(data, "nothing", &value) && !cz_json_member((cz_span){ "{\"a\":", 5 }, "a", &value));
    expect("json: a string that does not fit is refused", cz_json_member(peer, "name", &value) && !cz_json_string(value, text, 5));
    expect("json: quoting", cz_json_quote(text, sizeof text, "a\"b\\c\n") > 0 && strcmp(text, "\"a\\\"b\\\\c\\u000a\"") == 0);

    cz_url url;
    expect("url: with port and path", cz_url_parse("http://127.0.0.1:9021/api/connectivitizer/", &url) && !url.secure && url.port == 9021
                                          && strcmp(url.host, "127.0.0.1") == 0 && strcmp(url.path, "/api/connectivitizer") == 0);
    expect("url: defaults", cz_url_parse("wss://relay.example.com", &url) && url.secure && url.port == 443 && strcmp(url.path, "/") == 0);
    expect("url: other schemes are refused", !cz_url_parse("ftp://example.com", &url));

    printf(failures == 0 ? "\nall checks passed\n" : "\n%d check(s) FAILED\n", failures);
    return failures == 0 ? 0 : 1;
}

/* ---- Device ------------------------------------------------------------------------------- */

static const char *env(const char *name, const char *fallback)
{
    const char *value = getenv(name);
    return value != NULL && value[0] != '\0' ? value : fallback;
}

int main(int argc, char **argv)
{
    if (argc > 1 && strcmp(argv[1], "selftest") == 0) {
        return selftest();
    }

    char host[64] = "127.0.0.1";
    const char *target = env("CZ_TARGET", NULL);
    const char *colon = target != NULL ? strrchr(target, ':') : NULL;
    if (colon == NULL || (size_t)(colon - target) >= sizeof host) {
        fprintf(stderr, "CZ_TARGET must be host:port\n");
        return 64;
    }
    memcpy(host, target, (size_t)(colon - target));
    host[colon - target] = '\0';

    cz_config config;
    memset(&config, 0, sizeof config);
    config.api_url = env("CZ_API_URL", NULL);
    config.device_key = env("CZ_DEVICE_KEY", NULL);
    config.name = env("CZ_DEVICE_NAME", NULL);
    config.shared_keys[0] = env("CZ_SHARED_KEY", NULL);
    config.services[0].name = env("CZ_SERVICE", "api");
    config.services[0].host = host;
    config.services[0].port = (uint16_t)atoi(colon + 1);
    config.services[0].protocol = "http";
    config.disable_peer_to_peer = strcmp(env("CZ_DIRECT", ""), "none") == 0;
    config.include_loopback = strcmp(env("CZ_LOOPBACK", ""), "true") == 0;
    config.log = log_line;

    cz_agent *agent = cz_agent_create(&config);
    if (agent == NULL) {
        return 64;
    }
    running = agent;
#if defined(_WIN32)
    _beginthreadex(NULL, 0, watch_stdin, NULL, 0, NULL);
#else
    pthread_t watcher;
    pthread_create(&watcher, NULL, watch_stdin, NULL);
#endif

    bool announced = false;
    cz_status status;
    for (;;) {
        cz_agent_poll(agent, 50);
        cz_agent_get_status(agent, &status);
        if (!announced && status.state == CZ_STATE_ONLINE) {
            announced = true;
            printf("READY\n");
            fflush(stdout);
        }
        if (status.state == CZ_STATE_REFUSED) {
            printf("STOPPED %s\n", status.last_error);
            fflush(stdout);
            return 2;
        }
        /* cz_agent_stop was called from the stdin watcher. */
        if (cz_agent_stopping(agent)) {
            break;
        }
    }
    cz_agent_destroy(agent);
    return 0;
}
