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

    /** The last error code, or an empty string. */
    const char *lastError();

private:
    cz_config _config = {};
    cz_agent *_agent = nullptr;
    void *_task = nullptr;
    cz_status _status = {};
    int _keys = 0;
    int _services = 0;
};

extern ConnectivitizerClass Connectivitizer;

#endif
#endif
