/*
  Connectivitizer - an ESP32 web server you can reach from anywhere (peer to peer)

  Like the RelayOnly example, but app and ESP32 first try to talk to each other directly: in the
  same Wi-Fi the data never leaves it, across the internet it goes straight from one router to
  the other, and from a phone on mobile data it goes over IPv6 where phone and home network both
  have it (the library switches IPv6 on by itself). Where none of that is possible (company
  networks, mobile data without IPv6) the connection falls back to the relay by itself. Either
  way it is encrypted end to end with the shared key below, and the app shows which path is in use.

  What you need (https://connectivitizer.com, or your own installation):
    1. a device key   - Credentials > Create credential > Device key   -> DEVICE_KEY
    2. a shared key   - Credentials > Generate a shared key            -> SHARED_KEY, and the same key in your app
  No other library has to be installed.
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
  json += ",\"appsConnected\":";
  json += Connectivitizer.sessions();
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
  Connectivitizer.expose("api", 80);   // the web server above, under the name "api"
  // Peer to peer is on unless switched off: nothing to set.
  if (!Connectivitizer.begin(DEVICE_KEY, DEVICE_NAME)) {
    Serial.println("Connectivitizer: check DEVICE_KEY, DEVICE_NAME and SHARED_KEY");
  }
}

void loop() {
  server.handleClient();

  // Optional: tell on the serial monitor when the connection to the platform changes.
  static bool wasConnected = false;
  bool isConnected = Connectivitizer.connected();
  if (isConnected != wasConnected) {
    wasConnected = isConnected;
    Serial.println(isConnected ? "Reachable through Connectivitizer." : "Not reachable right now.");
  }
  if (Connectivitizer.refused()) {
    Serial.printf("The platform refused this device: %s\n", Connectivitizer.lastError());
    delay(10000);
  }
}
