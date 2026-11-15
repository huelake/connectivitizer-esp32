// Copy this file to secrets.h (same folder; it is not committed) and fill it in.

#define WIFI_SSID "your-wifi"
#define WIFI_PASSWORD "your-wifi-password"

// From your workspace in the web app:
//   Credentials > Create credential > Device key
//   Credentials > Generate a shared key   (the same key goes into your app)
#define DEVICE_KEY "czd_..."
#define DEVICE_NAME "living-room-lamp" // how your app addresses this device
#define SHARED_KEY "czs_..."

// 1: app and ESP32 talk directly when the networks allow it, and through the relay when not.
// 0: always through the relay.
#define PEER_TO_PEER 1

// Only for a platform of your own. Leave it out for connectivitizer.com.
// A development platform on your PC: the API address that run-lan.ps1 prints.
// #define SERVER_URL "http://192.168.1.10:9021/api/connectivitizer"
