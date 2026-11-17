/*
 * One ESP32 calls another: this sketch reads the state of a second device of the same workspace
 * every ten seconds and prints it. The other device runs the PeerToPeer example (or anything that
 * exposes a service "api" with GET /state), under the name given in OTHER_DEVICE.
 *
 * Needs, in the web app under Credentials:
 *  - a device key with "Its devices may open sessions to other devices" switched on (DEVICE_KEY),
 *  - the shared key the other device holds (SHARED_KEY).
 *
 * This device is reachable itself as well: its own GET /state says what it last read.
 */
#include <WiFi.h>
#include <WebServer.h>
#include <Connectivitizer.h>

const char *WIFI_SSID = "your-wifi";
const char *WIFI_PASSWORD = "your-wifi-password";
const char *DEVICE_KEY = "czd_...";
const char *SHARED_KEY = "czs_...";
const char *DEVICE_NAME = "reader";
const char *OTHER_DEVICE = "living-room-lamp";

WebServer server(80);
String lastAnswer = "{}";
int lastStatus = 0;
unsigned long lastRead = 0;

void setup() {
  Serial.begin(115200);
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);

  server.on("/state", HTTP_GET, []() {
    server.send(200, "application/json", String("{\"status\":") + lastStatus + ",\"other\":" + lastAnswer + "}");
  });
  server.begin();

  Connectivitizer.setLog(Serial);
  Connectivitizer.setSharedKey(SHARED_KEY);
  Connectivitizer.expose("api", 80);
  // The service "api" of the other device, on port 8081 of this one.
  Connectivitizer.link(OTHER_DEVICE, "api", 8081);
  Connectivitizer.begin(DEVICE_KEY, DEVICE_NAME);
}

void loop() {
  server.handleClient();

  if (Connectivitizer.connected() && millis() - lastRead > 10000) {
    lastRead = millis();
    String answer;
    lastStatus = Connectivitizer.get(OTHER_DEVICE, "/state", answer);
    if (lastStatus == 200) {
      lastAnswer = answer;
      Serial.println("the other device says: " + answer);
    } else {
      Serial.printf("no answer (status %d, %s)\n", lastStatus, Connectivitizer.lastError());
    }
  }
}
