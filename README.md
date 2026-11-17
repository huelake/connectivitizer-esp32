# Connectivitizer for ESP32

Reach a web server on your ESP32 from your app, from anywhere, without opening a port in any router. The connection is encrypted end to end with a key only your device and your app hold, and runs through the Connectivitizer relay or peer to peer.

The library needs no other library.

```cpp
#include <WiFi.h>
#include <WebServer.h>
#include <Connectivitizer.h>

WebServer server(80);

void setup() {
  WiFi.begin("your-wifi", "your-wifi-password");
  server.on("/state", []() { server.send(200, "application/json", "{\"ok\":true}"); });
  server.begin();

  Connectivitizer.setSharedKey("czs_...");               // the same key your app has
  Connectivitizer.expose("api", 80);                     // the web server above
  Connectivitizer.begin("czd_...", "living-room-lamp");  // device key, and the device's name
}

void loop() { server.handleClient(); }
```

The device appears in your workspace the first time it connects. An app then reaches it by its name:

```ts
const session = await client.connect('living-room-lamp', ['api']);
const state = await (await session.fetch('api', '/state')).json();
```

## What you need

| | Where it comes from | Where it goes |
|---|---|---|
| **Device key** `czd_…` | Web app: *Credentials → Create credential → Device key* | `begin()`. One key serves any number of devices; each logs in under its own name. |
| **Name** | You choose it | `begin()`. It is how apps address the device, so it stays the same. Give the device a friendlier alias in the web app. |
| **Shared key** `czs_…` | Web app: *Credentials → Generate a shared key* (made in your browser), or `npx connectivitizer keygen`, or `cz key new` | `setSharedKey()` on the device, and the same key in the app. It is never sent to Connectivitizer. |

## Install

- **Arduino IDE**: *Tools → Manage Libraries*, search for **Connectivitizer**, *Install*; then *File → Examples → Connectivitizer*. Or `arduino-cli lib install Connectivitizer`.
- **PlatformIO**: `lib_deps = huelakesoftwaresolutions/Connectivitizer` in `platformio.ini`.
- **ESP-IDF**: `idf.py add-dependency "huelake/connectivitizer"` and use `cz.h` (see `examples/esp-idf`). The application needs the 1.5 MB app partition on the newer chips (`CONFIG_PARTITION_TABLE_SINGLE_APP_LARGE=y`).

## Examples

| Example | Path |
|---|---|
| `examples/RelayOnly` | Every connection goes through the relay. Works in every network. |
| `examples/PeerToPeer` | App and ESP32 talk directly when the networks allow it, and fall back to the relay when not. |
| `examples/platformio` | The same web server as a PlatformIO project, with Wi-Fi and keys in a file that is not committed, and a setting for a platform of your own. |
| `examples/esp-idf` | The same without Arduino, with `esp_http_server`. |
| `examples/Link` | One ESP32 calls another: it reads `GET /state` of a second device every ten seconds, and is reachable itself. |

Both Arduino examples serve `GET /state` and `POST /led`. An app reaches them with any of the Connectivitizer SDKs (.NET, TypeScript, React Native, Python, JVM); [the guides](https://connectivitizer.com/guides/llms.md) show how.

## Calling another device

An ESP32 can reach a service of another device of your workspace: a second ESP32, a Raspberry Pi, a PC.

```cpp
Connectivitizer.link("cabin", "api", 8081);        // before begin(): the service "api" of the device "cabin"
Connectivitizer.begin(DEVICE_KEY, DEVICE_NAME);

String answer;
int status = Connectivitizer.get("cabin", "/state", answer);   // in loop(): the HTTP status, or -1
```

After `link`, the other device's service is at `127.0.0.1:8081` on the ESP32. `get` and `post` are a small HTTP client for it; any other library that speaks TCP can connect to the port as well (`HTTPClient`, a WebSocket or MQTT client). The session to the other device is opened by the first connection, which takes a few seconds, and closed after 30 seconds without one. It is encrypted end to end with the shared key the other device holds, and runs peer to peer or through the relay like every session.

Two things are needed in the workspace: the device key must have *Its devices may open sessions to other devices* switched on (where the key is created or edited; without it the log says `FORBIDDEN`), and both devices hold the same shared key, or the other device's key is passed as the fourth argument of `link`.

## Reference

| Call | Meaning |
|---|---|
| `setSharedKey(key)` | A key apps must hold to reach the device. Call again to add more (up to 4), for example one per app. |
| `expose(name, port, host, protocol)` | Makes a TCP service reachable under `name`. `host` may be another machine in the same network; leave it out for the ESP32 itself. Up to 4 services. |
| `link(device, service, port, sharedKey)` | Makes `service` of another device reachable at `127.0.0.1:port` on the ESP32. Up to 2 links (`CZ_MAX_LINKS`). |
| `get(device, path, response)`, `post(device, path, body, response)` | An HTTP request to a linked device. Returns the HTTP status, or -1 when the device was not reached in time. |
| `linkPort(device)`, `links()` | The port of a link, and how many sessions the ESP32 has open to other devices. |
| `setPeerToPeer(false)` | Never connect directly; always use the relay. |
| `setServer(url)` | The API of your own installation instead of connectivitizer.com. |
| `setRootCA(pem)` | A certificate authority for the connections to the platform (see below). |
| `setLog(Serial)` | Print what the library does. |
| `begin(deviceKey, name)` | Start. Returns false when a setting is not valid. |
| `connected()`, `sessions()`, `refused()`, `lastError()` | State, for a status LED or a display. |
| `end()` | Stop and free everything. |

Settings are made before `begin()`. The library runs in a task of its own; `loop()` does not have to call it.

## What it does and what it costs

- **Peer to peer** uses UDP: within the same Wi-Fi by the local address, across the internet by hole punching through the routers, and over IPv6 where the router hands out IPv6 addresses. That last one is what makes a phone on mobile data reach the device directly, since mobile IPv4 goes through the carrier's NAT. The library switches IPv6 on for the Wi-Fi (or Ethernet) interface itself when it connects; a sketch does not have to call `WiFi.enableIPv6()`. With `setLog(Serial)` every session logs the addresses both sides offered, and either the address the app was reached at or why the session went through the relay; [the troubleshooting guide](https://connectivitizer.com/guides/troubleshooting.md) explains the lines.
- **Services are TCP ports.** Whatever serves the port works unchanged: the core's `WebServer`, ESPAsyncWebServer, `esp_http_server`, WebSockets included. The service sees an ordinary local connection.
- **Encryption** between app and device is the Noise handshake `NNpsk0` (X25519, ChaCha20-Poly1305, SHA-256) with your shared key; each connection agrees on fresh keys. The relay forwards ciphertext. Connectivitizer never receives the shared key.
- **Connections to the platform** use the TLS of the board package (`esp_tls`) and trust the two Let's Encrypt root certificates that are compiled in (`src/port/cz_roots.h`). An installation with a certificate from another authority passes that authority's certificate with `setRootCA()`.
- **Sessions:** one app at a time by default; a new connection replaces the old one. Set `-DCZ_MAX_SESSIONS=2` to allow more. Six simultaneous requests per session (`CZ_MAX_STREAMS`). Each link has a session of its own while it is in use; those are not replaced by apps that connect.
- **Memory:** an idle device holds one TLS connection to the platform and about 9 KB besides. A session adds about 10 KB. Through the relay it also holds a second TLS connection; peer to peer it holds KCP buffers instead (at most about 50 KB under load, `CZ_KCP_WINDOW`). With the board packages' fixed TLS buffers one TLS connection is roughly 40 KB. A session the ESP32 opens for a link costs the same as one opened to it. These figures are estimates; check `ESP.getFreeHeap()` on your board.
- **Flash:** the sketch of the example is about 970 KB on an ESP32, most of which is Wi-Fi and TLS from the board package.
- **Time:** the device takes the time from the platform; no NTP is needed.

## Chips and board packages

| | Checked how |
|---|---|
| ESP32, ESP32-S2, ESP32-S3, ESP32-C3 with Arduino core 2.0.17 | Both Arduino examples compile (PlatformIO `espressif32` 6.12.0). |
| ESP32, ESP32-S2, ESP32-C2, ESP32-C5, ESP32-C6, ESP32-C61 with ESP-IDF 5.5 | The library as a component and `examples/esp-idf` compile and link (`espressif/idf:release-v5.5`). |
| The protocol code itself | Runs on a PC (`host/`) against the control plane and the relay, with the .NET library and the TypeScript SDK as the calling side, through the relay and peer to peer. |
| Calling another device (`link`) | The protocol code runs on a PC (`host/`) as the calling side against a .NET device and against itself, through the relay and peer to peer, with lease renewal and revocation. `examples/Link` compiles for ESP32, S2, S3 and C3 (Arduino core 2.0.17). On an ESP32-S3 only the port on the loopback address was tried, not a session. |
| Arduino core 3.x (needed for ESP32-C5 and -C6 with Arduino) | Not compiled. It is built on ESP-IDF 5, for which the library compiles. |
| ESP32-C2, -C61 | ESP-IDF only: there is no Arduino core for them. The C2 has little memory for two TLS connections. |
| On a chip | Run on an ESP32-S3 with ESP-IDF 5.5. |

## Limits

- The device key and the shared key are in the firmware. Whoever reads the flash has both; use flash encryption if that matters for your product. A device key alone lets someone register devices in your workspace and, if it allows its devices to open sessions, ask for sessions within its access rules; it does not let anyone read traffic or take part in a session without the shared key.
- A link's port is open to everything that runs on the ESP32, and to nothing else: it listens on the loopback address.
- `get` and `post` hold the whole answer in memory and block the calling task until it is there. For large answers connect to the port yourself and read in pieces.
- While a large transfer waits for a slow receiver on the relay path, the library's task waits with it (up to 15 s), and other requests of that session wait too.
- Certificates and pairing, the other way of trusting that `cz` and the .NET library offer, are not available on the ESP32: the board packages have no TLS 1.3.

## Trying it without a chip

`host/` builds the same code for a PC. `host\build.cmd` (Windows, Visual Studio 2022) or `host/build.sh` (Linux, macOS) produce `host/build/cz_host`:

```
cz_host selftest        # checks the cryptography against published test vectors
cz_host                 # runs a device; configuration through CZ_API_URL, CZ_DEVICE_KEY, CZ_DEVICE_NAME, CZ_SHARED_KEY, CZ_TARGET
                        # CZ_LINK=<device>/<service>=<port> adds a link to another device
```

The PC build speaks plain `http://`/`ws://` to the platform, so it runs a device only against an installation of your own that offers that.

## Third-party source in this library

Compiled in unchanged, under `src/vendor/`; licences in `third-party/`.

| | Used for | Licence |
|---|---|---|
| Monocypher 4.0.2 (Loup Vaillant) | X25519, ChaCha20-Poly1305 | BSD-2-Clause or CC0 |
| KCP, revision b1a7a21 (Lin Wei) | Reliable stream over UDP for peer-to-peer | MIT |
| micro-ecc, revision 541b3a7 (Ken MacKay) | Verifying the platform's signature on session grants | BSD-2-Clause |
