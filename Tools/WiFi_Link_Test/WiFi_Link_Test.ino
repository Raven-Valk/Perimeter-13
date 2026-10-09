// =====================================================================
//  Project 13 — Wi-Fi link test (gateway <-> laptop)
//  Any ESP32. 1) Scans and lists every Wi-Fi network it can see
//  (the ESP32 only sees 2.4 GHz, so this shows whether the hotspot is
//  usable). 2) Joins the hotspot. 3) Every 5 s fetches a page from the
//  test server on the laptop and prints channel, signal strength and
//  whether the laptop answered.
//  Serial Monitor: 115200 baud.
//
//  Test server on the laptop (shares ONE test page, hotspot only):
//    mkdir C:\p13test
//    cd /d C:\p13test
//    echo P13 test OK > index.html
//    python -m http.server 8000 --bind 192.168.137.1
//  Never run http.server from your user folder: it shares everything in it.
// =====================================================================
#include <WiFi.h>
#include <HTTPClient.h>

const char* WIFI_NAME_HAS = "LAPTOP-PAV";       // part of the hotspot's name (it joins the first match)
const char* WIFI_PASSWORD = "TYPE-PASSWORD";    // the hotspot's password
const char* LAPTOP_IP     = "192.168.137.1";    // laptop's address on the hotspot (ipconfig)
const int   LAPTOP_PORT   = 8000;

String ssid;
uint32_t ok = 0, fail = 0, drops = 0;
bool wasConnected = false;
uint32_t joinStart = 0;

void setup() {
  Serial.begin(115200);
  delay(1500);
  WiFi.mode(WIFI_STA);
  WiFi.setSleep(false);                          // the real gateway also needs this for ESP-NOW

  Serial.println("\n=== Scanning Wi-Fi (2.4 GHz only) ===");
  int n = WiFi.scanNetworks();
  for (int i = 0; i < n; i++) {
    bool match = WiFi.SSID(i).indexOf(WIFI_NAME_HAS) >= 0;
    Serial.printf("%s ch %2d  %4d dBm  %s\n", match ? ">>" : "  ",
                  (int)WiFi.channel(i), (int)WiFi.RSSI(i), WiFi.SSID(i).c_str());
    if (match && ssid.length() == 0) ssid = WiFi.SSID(i);
  }
  if (ssid.length() == 0) {
    Serial.printf("\nHOTSPOT NOT FOUND: no network name contains \"%s\".\n", WIFI_NAME_HAS);
    Serial.println("It is probably running on 5 GHz (the ESP32 can't see 5 GHz). Stopping.");
    while (true) delay(1000);
  }
  Serial.printf("\nHotspot found: \"%s\". Joining ...\n", ssid.c_str());
  WiFi.begin(ssid.c_str(), WIFI_PASSWORD);
  joinStart = millis();
}

void loop() {
  if (WiFi.status() != WL_CONNECTED) {
    if (wasConnected) { drops++; wasConnected = false; Serial.println("!! Wi-Fi DROPPED"); joinStart = millis(); }
    if (millis() - joinStart > 20000) {
      Serial.printf("\nStill not joined after 20 s (status %d). Wrong password? Retrying ...\n", (int)WiFi.status());
      WiFi.disconnect();
      WiFi.begin(ssid.c_str(), WIFI_PASSWORD);
      joinStart = millis();
    }
    Serial.print(".");
    delay(500);
    return;
  }
  if (!wasConnected) {
    wasConnected = true;
    Serial.printf("\nConnected. ESP32 IP %s | channel %d | signal %d dBm\n",
                  WiFi.localIP().toString().c_str(), (int)WiFi.channel(), (int)WiFi.RSSI());
  }

  HTTPClient http;
  String url = String("http://") + LAPTOP_IP + ":" + LAPTOP_PORT + "/";
  http.setTimeout(3000);
  http.begin(url);
  int code = http.GET();
  http.end();
  if (code > 0) ok++; else fail++;

  int rssi = WiFi.RSSI();
  const char* quality = rssi > -60 ? "excellent" : rssi > -70 ? "good" : rssi > -80 ? "weak" : "too weak";
  Serial.printf("channel %2d | signal %4d dBm (%s) | laptop %s | ok %lu  fail %lu  drops %lu\n",
                (int)WiFi.channel(), rssi, quality, code > 0 ? "ANSWERED" : "NO ANSWER",
                (unsigned long)ok, (unsigned long)fail, (unsigned long)drops);
  delay(5000);
}
