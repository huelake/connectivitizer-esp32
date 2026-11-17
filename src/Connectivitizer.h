/*
 * Connectivitizer for ESP32 - make a web server on your ESP32 reachable from your app, from
 * anywhere, without opening a port: end-to-end encrypted, through the relay or peer to peer.
 *
 *   #include <Connectivitizer.h>
 *
 *   Connectivitizer.setSharedKey("czs_...");            // the same key your app has
 *   Connectivitizer.expose("api", 80);                  // the web server of this sketch
 *   Connectivitizer.begin("czd_...", "living-room-lamp"); // device key and the device's name
 *
 * Nothing else is needed: the library runs in a task of its own, reconnects by itself, and the
 * device appears in your Connectivitizer workspace the first time it connects.
 *
 * The device can also call another device of the workspace:
 *
 *   Connectivitizer.link("cabin", "api", 8081);          // before begin()
 *   int status = Connectivitizer.get("cabin", "/state", answer);
 *
 * The other device's service is then at 127.0.0.1:8081 on this device, for any library that
 * speaks TCP. The device key needs "Its devices may open sessions to other devices".
 */
#ifndef CONNECTIVITIZER_H
#define CONNECTIVITIZER_H

#include "cz.h"

#ifdef __cplusplus

#if defined(ARDUINO)
#include <Arduino.h>
#endif

class ConnectivitizerClass {
public:
    /** The API of your Connectivitizer installation. Only needed when it is not connectivitizer.com. */
    void setServer(const char *apiUrl);

    /**
     * The key this device shares with the apps that connect to it (czs_...). Everything between
     * app and device is encrypted with it; Connectivitizer never has it. Call it again to add
     * a second key, for example one per app.
     */
    bool setSharedKey(const char *key);

    /**
     * Makes a TCP service reachable under a name, for example the web server of this sketch:
     * expose("api", 80). Nothing is reachable that is not exposed here. `host` may name another
     * machine in the same network; leave it out for this device itself.
     */
    bool expose(const char *name, uint16_t port, const char *host = nullptr, const char *protocol = "http");

    /**
     * Makes a service of another device of your workspace reachable on a port of this device:
     * after link("cabin", "api", 8081), whatever connects to 127.0.0.1:8081 talks to the service
     * "api" of the device "cabin", end-to-end encrypted. The session to the other device is opened
     * by the first connection and closed when the port has not been used for half a minute.
     *
     * Needs a device key whose devices may open sessions (set in the web app where the key is
     * created). \`sharedKey\` is the key the other device holds; leave it out when it is the one
     * given to setSharedKey first. Call it before begin().
     */
    bool link(const char *device, const char *service, uint16_t localPort, const char *sharedKey = nullptr);

    /** The local port of a link, or 0 when there is none to that device (and service, if given). */
    uint16_t linkPort(const char *device, const char *service = nullptr);

#if defined(ARDUINO)
    /**
     * An HTTP request to a linked device: get("cabin", "/state", answer). Returns the HTTP status
     * and puts the body into \`response\`; -1 when the other device could not be reached in time
     * (lastError() then names the reason once the library knows it). It waits for the answer, at
     * most \`timeoutMs\`; opening the session the first time takes a few seconds of that.
     */
    int get(const char *device, const char *path, String &response, uint32_t timeoutMs = 15000);

    /** As get(), sending \`body\` (JSON unless \`contentType\` says otherwise). */
    int post(const char *device, const char *path, const String &body, String &response, uint32_t timeoutMs = 15000, const char *contentType = "application/json");
#endif

    /** Peer-to-peer connections are tried first and the relay is the fallback. false: always use the relay. */
    void setPeerToPeer(bool enabled);

    /** A certificate authority (PEM) for the connections to the platform, instead of the built-in ones. */
    void setRootCA(const char *pem);

#if defined(ARDUINO)
    /** Prints what the library does (connected, session established, refused, ...) to e.g. Serial. */
    void setLog(Print &out);
#endif

    /**
     * Starts the device: `deviceKey` (czd_...) is created in your workspace, `name` is what the
     * device is called there and how apps address it. Returns false when a setting is not valid
     * (the reason is logged). Connecting happens in the background, also when Wi-Fi comes up later.
     */
    bool begin(const char *deviceKey, const char *name);

    /** Ends all sessions and disconnects. */
    void end();

    /** True while the device is connected to the platform and apps can reach it. */
    bool connected();

    /** True when the platform refused the device key. The library has stopped then. */
    bool refused();

    /** How many apps are connected right now. */
    int sessions();

    /** How many sessions this device has open to other devices right now. */
    int links();

    /** The last error code, or an empty string. */
    const char *lastError();

private:
    cz_config _config = {};
    cz_agent *_agent = nullptr;
    void *_task = nullptr;
    cz_status _status = {};
    int _keys = 0;
    int _services = 0;
    int _links = 0;
#if defined(ARDUINO)
    int request(const char *method, const char *device, const char *path, const String *body, const char *contentType, String &response, uint32_t timeoutMs);
#endif
};

extern ConnectivitizerClass Connectivitizer;

#endif
#endif
