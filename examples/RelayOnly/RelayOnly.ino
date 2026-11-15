/*
  Connectivitizer - an ESP32 web server you can reach from anywhere (relay only)

  The sketch runs an ordinary web server on port 80 and makes it reachable from your app through
  Connectivitizer. Every connection goes through the relay, encrypted end to end with the shared
  key below: the relay only forwards bytes it cannot read. This is the variant that works in
  every network. See the PeerToPeer example for direct connections.

  What you need (https://connectivitizer.com, or your own installation):
    1. a device key   - Credentials > Create credential > Device key   -> DEVICE_KEY
    2. a shared key   - Credentials > Generate a shared key            -> SHARED_KEY, and the same key in your app
  No other library has to be installed.

  The device appears in your workspace under DEVICE_NAME the first time it connects.
*/
#include <WiFi.h>
#include <WebServer.h>
#include <Connectivitizer.h>

const char *WIFI_SSID = "your-wifi";
const char *WIFI_PASSWORD = "your-wifi-password";

const char *DEVICE_KEY = "czd_...";           // from your workspace
const char *DEVICE_NAME = "living-room-lamp"; // how your app addresses this device
const char *SHARED_KEY = "czs_...";           // the same key your app has; never sent to anyone

#ifndef LED_BUILTIN
#define LED_BUILTIN 2
#endif

WebServer server(80);
bool ledOn = false;

void sendState() {
  String json = "{\"led\":";
  json += ledOn ? "true" : "false";
  json += ",\"uptimeSeconds\":";
  json += millis() / 1000;
  json += ",\"freeHeap\":";
  json += ESP.getFreeHeap();
  json += ",\"rssi\":";
  json += WiFi.RSSI();
  json += "}";
  server.send(200, "application/json", json);
}

void setup() {
  Serial.begin(115200);
  pinMode(LED_BUILTIN, OUTPUT);

  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);

  // An ordinary web server. It knows nothing about Connectivitizer.
  server.on("/state", HTTP_GET, sendState);
  server.on("/led", HTTP_POST, []() {
    String wanted = server.arg("plain");
    ledOn = wanted == "toggle" ? !ledOn : wanted == "on";
    digitalWrite(LED_BUILTIN, ledOn ? HIGH : LOW);
    sendState();
  });
  server.begin();

  Connectivitizer.setLog(Serial);
  Connectivitizer.setSharedKey(SHARED_KEY);
  Connectivitizer.expose("api", 80);      // the web server above, under the name "api"
  Connectivitizer.setPeerToPeer(false);   // always through the relay
  if (!Connectivitizer.begin(DEVICE_KEY, DEVICE_NAME)) {
    Serial.println("Connectivitizer: check DEVICE_KEY, DEVICE_NAME and SHARED_KEY");
  }
}

void loop() {
  server.handleClient();
}
