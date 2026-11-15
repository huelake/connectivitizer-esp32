/*
  Connectivitizer - an ESP32 web server you can reach from anywhere (PlatformIO project)

  The same web server as the Arduino examples RelayOnly and PeerToPeer: GET /state and POST /led.
  What you change is in include/secrets.h; copy include/secrets.example.h to get one.
*/
#include <Arduino.h>
#include <WiFi.h>
#include <WebServer.h>
#include <Connectivitizer.h>

#include "secrets.h"

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
  Serial.print("Wi-Fi");
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }
  Serial.print(" connected, address ");
  Serial.println(WiFi.localIP());

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
#ifdef SERVER_URL
  Connectivitizer.setServer(SERVER_URL);
#endif
  Connectivitizer.setSharedKey(SHARED_KEY);
  Connectivitizer.setPeerToPeer(PEER_TO_PEER);
  Connectivitizer.expose("api", 80);   // the web server above, under the name "api"
  if (!Connectivitizer.begin(DEVICE_KEY, DEVICE_NAME)) {
    Serial.println("Connectivitizer: check DEVICE_KEY, DEVICE_NAME and SHARED_KEY");
  }
}

void loop() {
  server.handleClient();

  static bool wasConnected = false;
  bool isConnected = Connectivitizer.connected();
  if (isConnected != wasConnected) {
    wasConnected = isConnected;
    Serial.println(isConnected ? "Reachable through Connectivitizer." : "Not reachable right now.");
  }

  // Once a minute: how much memory is left, and whether an app is connected.
  static unsigned long lastReport = 0;
  if (millis() - lastReport > 60000) {
    lastReport = millis();
    Serial.printf("free heap %u bytes, apps connected: %d\n", (unsigned)ESP.getFreeHeap(), Connectivitizer.sessions());
  }

  if (Connectivitizer.refused()) {
    Serial.printf("The platform refused this device: %s\n", Connectivitizer.lastError());
    delay(10000);
  }
}
