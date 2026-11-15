/*
 * Connectivitizer for ESP32 - the device side of the Connectivitizer protocol in portable C.
 *
 * A device logs in with a device key under a fixed name, declares local TCP services and serves
 * them to applications that hold the same shared key: through the relay, or peer to peer.
 * Everything between the application and the device is encrypted end to end with that key; the
 * platform never has it.
 *
 * Arduino sketches use the wrapper in Connectivitizer.h. This header is the C interface behind
 * it, for ESP-IDF projects and for tests on a PC.
 */
#ifndef CZ_H
#define CZ_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CZ_VERSION "1.0.33"

/* Limits. They decide how much memory an agent uses; change them with compiler definitions. */
#ifndef CZ_MAX_SERVICES
#define CZ_MAX_SERVICES 4
#endif
#ifndef CZ_MAX_SHARED_KEYS
#define CZ_MAX_SHARED_KEYS 4
#endif
#ifndef CZ_MAX_SESSIONS
#if defined(ESP_PLATFORM)
#define CZ_MAX_SESSIONS 1 /* a session over the relay holds a TLS connection: about 45 KB of heap */
#else
#define CZ_MAX_SESSIONS 4
#endif
#endif
#ifndef CZ_MAX_STREAMS
#define CZ_MAX_STREAMS 6 /* simultaneous connections to local services within one session */
#endif

#define CZ_DEFAULT_API_URL "https://api.connectivitizer.com/api/connectivitizer"

typedef void (*cz_log_fn)(const char *line, void *user);

typedef struct {
    const char *name;     /* what applications ask for, e.g. "api" */
    const char *host;     /* where it runs; NULL means this device itself (127.0.0.1) */
    uint16_t port;
    const char *protocol; /* "http", "ws" or "tcp"; shown in the web app, NULL means "tcp" */
} cz_service;

typedef struct {
    const char *api_url;    /* NULL: CZ_DEFAULT_API_URL */
    const char *device_key; /* czd_..., created in the workspace */
    const char *name;       /* the device's name; it is how the device is addressed and does not change */
    const char *shared_keys[CZ_MAX_SHARED_KEYS]; /* czs_..., the same key the applications hold */
    cz_service services[CZ_MAX_SERVICES];        /* unused entries have a NULL name */
    bool disable_peer_to_peer; /* true: always use the relay */
    const char *root_ca_pem;   /* certificate authority for the connections to the platform; NULL: the built-in ones (Let's Encrypt) */
    const char *platform;      /* shown in the web app, e.g. "esp32-c3"; NULL: detected */
    bool include_loopback;     /* offer 127.0.0.1 for peer-to-peer; only useful for tests on one machine */
    cz_log_fn log;             /* receives one line per noteworthy event; may be NULL */
    void *log_user;
} cz_config;

typedef enum {
    CZ_STATE_OFFLINE = 0, /* not connected to the platform (yet); the agent keeps trying */
    CZ_STATE_ONLINE,      /* connected: applications can reach the device */
    CZ_STATE_REFUSED      /* the platform does not accept the device key; the agent has stopped */
} cz_state;

typedef struct {
    cz_state state;
    int sessions;        /* sessions open right now */
    char last_error[40]; /* the last error code, empty if none */
    char device_id[40];  /* the id the platform gave the device */
} cz_status;

typedef struct cz_agent cz_agent;

/* Creates an agent. The configuration is copied; NULL when it is not valid (the reason is logged). */
cz_agent *cz_agent_create(const cz_config *config);

/*
 * Does what is due: connects when necessary, handles what arrived, sends what is waiting. Returns
 * after at most max_wait_ms when nothing happens; connecting to the platform can take longer.
 */
void cz_agent_poll(cz_agent *agent, int max_wait_ms);

/* Calls cz_agent_poll until cz_agent_stop is called from another task. */
void cz_agent_run(cz_agent *agent);

/* Asks the agent to stop. May be called from another task. */
void cz_agent_stop(cz_agent *agent);

/* True once cz_agent_stop was called. */
bool cz_agent_stopping(const cz_agent *agent);

void cz_agent_get_status(const cz_agent *agent, cz_status *out);

void cz_agent_destroy(cz_agent *agent);

#ifdef __cplusplus
}
#endif

#endif
