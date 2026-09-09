/***************************************************
  Main of FingerprintDoorbell 
 ****************************************************/

#include <WiFi.h>
#include <time.h>
#include <ESPAsyncWebServer.h>
#include <PubSubClient.h>
#include <HTTPClient.h>
#include <esp_task_wdt.h>
#include <Preferences.h>
#include "FingerprintManager.h"
#include "SettingsManager.h"
#include "global.h"
#include "WiFiManager.h"
#include "MQTTManager.h"
#include "WebUIHandler.h"

// Watchdog timeout (seconds) — if loop() doesn't feed WDT within this time, ESP reboots
#define WDT_TIMEOUT_SEC 60

// Crash recovery: after this many consecutive crashes, enter safe mode
#define MAX_CRASH_COUNT 3

// ===== Global variable DEFINITIONS =====
const char* VersionInfo = "0.9.3";
const int doorbellOutputPin = 19;
bool safeMode = false; // true = only WiFi+WebUI, no scanning/MQTT
unsigned long lastHeapCheck = 0;

#ifdef CUSTOM_GPIOS
  const int customOutput1 = 18;
  const int customOutput2 = 26;
  const int customInput1 = 21;
  const int customInput2 = 22;
  bool customInput1Value = false;
  bool customInput2Value = false;
#endif

const int logMessagesCount = 5;
String logMessages[logMessagesCount];
bool shouldReboot = false;
unsigned long wifiReconnectPreviousMillis = 0;
unsigned long mqttReconnectPreviousMillis = 0;
unsigned long mqttReconnectInterval = 5000;

String enrollId;
String enrollName;
Mode currentMode = Mode::scan;

FingerprintManager fingerManager;
SettingsManager settingsManager;
bool needMaintenanceMode = false;

AsyncWebServer webServer(80);
AsyncEventSource events("/events");

WiFiClient espClient;
PubSubClient mqttClient(espClient);
long lastMsg = 0;
char msg[50];
int value = 0;
bool mqttConfigValid = true;

Match lastMatch;


// ===== Helper functions (used by multiple modules) =====

void addLogMessage(const String& message) {
  for (int i = logMessagesCount - 1; i > 0; i--)
    logMessages[i] = logMessages[i - 1];
  logMessages[0] = message;
}

String getLogMessagesAsHtml() {
  String html = "";
  for (int i = logMessagesCount - 1; i >= 0; i--) {
    if (logMessages[i] != "")
      html = html + logMessages[i] + "<br>";
  }
  return html;
}

String getTimestampString(){
  struct tm timeinfo;
  if(!getLocalTime(&timeinfo)){
    Serial.println("Failed to obtain time");
    return "no time";
  }
  
  char buffer[25];
  strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S %Z", &timeinfo);
  String datetime = String(buffer);
  return datetime;
}

bool waitForMaintenanceMode() {
  needMaintenanceMode = true;
  unsigned long startMillis = millis();
  while (currentMode != Mode::maintenance) {
    if ((millis() - startMillis) >= 5000ul) {
      needMaintenanceMode = false;
      return false;
    }
    delay(50);
  }
  needMaintenanceMode = false;
  return true;
}

bool authenticateRequest(AsyncWebServerRequest *request) {
  if (!settingsManager.isAuthConfigured())
    return true;
  if (!request->authenticate(settingsManager.getAppSettings().adminUser.c_str(), 
                              settingsManager.getAppSettings().adminPassword.c_str())) {
    request->requestAuthentication();
    return false;
  }
  return true;
}

String urlDecode(const String& input) {
  String decoded = "";
  for (unsigned int i = 0; i < input.length(); i++) {
    if (input[i] == '%' && i + 2 < input.length()) {
      char hex[3] = { input[i+1], input[i+2], 0 };
      decoded += (char)strtol(hex, nullptr, 16);
      i += 2;
    } else if (input[i] == '+') {
      decoded += ' ';
    } else {
      decoded += input[i];
    }
  }
  return decoded;
}

void notifyClients(String message) {
  String messageWithTimestamp = "[" + getTimestampString() + "]: " + message;
  Serial.println(messageWithTimestamp);
  addLogMessage(messageWithTimestamp);
  events.send(getLogMessagesAsHtml().c_str(), "message", millis(), 1000);
  
  String mqttRootTopic = settingsManager.getAppSettings().mqttRootTopic;
  mqttClient.publish((String(mqttRootTopic) + "/lastLogMessage").c_str(), message.c_str());
}

void updateClientsFingerlist(String fingerlist) {
  Serial.println("New fingerlist was sent to clients");
  events.send(fingerlist.c_str(), "fingerlist", millis(), 1000);
}

bool doPairing() {
  String newPairingCode = settingsManager.generateNewPairingCode();

  if (fingerManager.setPairingCode(newPairingCode)) {
    AppSettings settings = settingsManager.getAppSettings();
    settings.sensorPairingCode = newPairingCode;
    settings.sensorPairingValid = true;
    settingsManager.saveAppSettings(settings);
    notifyClients("Pairing successful.");
    return true;
  } else {
    notifyClients("Pairing failed.");
    return false;
  }
}

bool checkPairingValid() {
  AppSettings settings = settingsManager.getAppSettings();

  if (!settings.sensorPairingValid) {
    if (settings.sensorPairingCode.isEmpty()) {
      return doPairing();
    } else {
      Serial.println("Pairing has been invalidated previously.");   
      return false;
    }
  }

  String actualSensorPairingCode = fingerManager.getPairingCode();

  if (actualSensorPairingCode.equals(settings.sensorPairingCode))
    return true;
  else {
    if (!actualSensorPairingCode.isEmpty()) { 
      AppSettings settings = settingsManager.getAppSettings();
      settings.sensorPairingValid = false;
      settingsManager.saveAppSettings(settings);
    }
    return false;
  }
}


// ===== HTTP Action helper =====
void fireHttpAction(const String& urlTemplate, int id, const String& name, int confidence) {
  if (urlTemplate.isEmpty()) return;
  
  String url = urlTemplate;
  url.replace("{id}", String(id));
  url.replace("{name}", name);
  url.replace("{confidence}", String(confidence));
  
  HTTPClient http;
  http.setTimeout(3000); // 3s timeout, don't block scanning
  http.begin(url);
  int httpCode = http.GET();
  if (httpCode > 0) {
    Serial.println("HTTP action: " + url + " -> " + String(httpCode));
  } else {
    Serial.println("HTTP action failed: " + url + " -> " + http.errorToString(httpCode));
  }
  http.end();
}

// ===== Server Mode event helper (ioBroker adapter) =====
// Minimal percent-encoding for query values (space, &, =, ?, #, +, %)
String urlEncodeValue(const String& value) {
  String out;
  const char* hex = "0123456789ABCDEF";
  for (size_t i = 0; i < value.length(); i++) {
    char c = value.charAt(i);
    if (isalnum((unsigned char)c) || c == '-' || c == '_' || c == '.' || c == '~') {
      out += c;
    } else {
      out += '%';
      out += hex[(c >> 4) & 0xF];
      out += hex[c & 0xF];
    }
  }
  return out;
}

// Sends an event to the registered server, e.g. path="match", query="id=5&name=Alex&confidence=180"
void fireServerEvent(const String& path, const String& query) {
  AppSettings s = settingsManager.getAppSettings();
  if (s.serverHost.isEmpty()) return;

  String url = "http://" + s.serverHost + ":" + String(s.serverPort) + "/" + path + "?";
  if (query.length() > 0) {
    url += query + "&";
  }
  url += "token=" + urlEncodeValue(s.serverToken);

  HTTPClient http;
  http.setTimeout(3000); // 3s timeout, don't block scanning
  http.begin(url);
  int httpCode = http.GET();
  if (httpCode > 0) {
    Serial.println("Server event: /" + path + " -> " + String(httpCode));
  } else {
    Serial.println("Server event failed: /" + path + " -> " + http.errorToString(httpCode));
  }
  http.end();
}

// ===== Core logic =====

void doScan()
{
  Match match = fingerManager.scanFingerprint();
  AppSettings appCfg = settingsManager.getAppSettings();
  String mqttRootTopic = appCfg.mqttRootTopic;
  bool serverMode = appCfg.serverMode;
  switch(match.scanResult)
  {
    case ScanResult::noFinger:
      if (match.scanResult != lastMatch.scanResult) {
        Serial.println("no finger");
        if (!serverMode) {
          mqttClient.publish((String(mqttRootTopic) + "/ring").c_str(), "off");
          mqttClient.publish((String(mqttRootTopic) + "/matchId").c_str(), "-1");
          mqttClient.publish((String(mqttRootTopic) + "/matchName").c_str(), "");
          mqttClient.publish((String(mqttRootTopic) + "/matchConfidence").c_str(), "-1");
        }
      }
      break; 
    case ScanResult::matchFound:
      notifyClients( String("Match Found: ") + match.matchId + " - " + match.matchName  + " with confidence of " + match.matchConfidence );
      if (checkPairingValid()) {
        if (serverMode) {
          // Server mode: send event only to the registered server (no MQTT, no legacy URLs)
          fireServerEvent("match", "id=" + String(match.matchId) + "&name=" + urlEncodeValue(match.matchName) + "&confidence=" + String(match.matchConfidence));
          Serial.println("Server event sent: match");
        } else {
          mqttClient.publish((String(mqttRootTopic) + "/ring").c_str(), "off");
          mqttClient.publish((String(mqttRootTopic) + "/matchId").c_str(), String(match.matchId).c_str());
          mqttClient.publish((String(mqttRootTopic) + "/matchName").c_str(), match.matchName.c_str());
          mqttClient.publish((String(mqttRootTopic) + "/matchConfidence").c_str(), String(match.matchConfidence).c_str());
          Serial.println("MQTT message sent: Open the door!");
          // HTTP action
          fireHttpAction(appCfg.httpMatchUrl, match.matchId, match.matchName, match.matchConfidence);
        }
      } else {
        notifyClients("Security issue! Match was not sent because of invalid sensor pairing! This could potentially be an attack! If the sensor is new or has been replaced by you do a (re)pairing in settings page.");
      }
      delay(3000);
      break;
    case ScanResult::noMatchFound:
      notifyClients(String("No Match Found (Code ") + match.returnCode + ")");
      fingerManager.setLedRingNoMatch();
      if (match.scanResult != lastMatch.scanResult) {
        digitalWrite(doorbellOutputPin, HIGH);
        if (serverMode) {
          fireServerEvent("ring", "");
          Serial.println("Server event sent: ring");
        } else {
          mqttClient.publish((String(mqttRootTopic) + "/ring").c_str(), "on");
          mqttClient.publish((String(mqttRootTopic) + "/matchId").c_str(), "-1");
          mqttClient.publish((String(mqttRootTopic) + "/matchName").c_str(), "");
          mqttClient.publish((String(mqttRootTopic) + "/matchConfidence").c_str(), "-1");
          Serial.println("MQTT message sent: ring the bell!");
          // HTTP action
          fireHttpAction(appCfg.httpRingUrl, 0, "", 0);
        }
        delay(1000);
        digitalWrite(doorbellOutputPin, LOW); 
      } else {
        delay(1000);
      }
      break;
    case ScanResult::error:
      notifyClients(String("ScanResult Error (Code ") + match.returnCode + ")");
      break;
  };
  lastMatch = match;
}

void doEnroll()
{
  int id = enrollId.toInt();
  if (id < 1 || id > 200) {
    notifyClients("Invalid memory slot id '" + enrollId + "'");
    return;
  }

  NewFinger finger = fingerManager.enrollFinger(id, enrollName);
  if (finger.enrollResult == EnrollResult::ok) {
    notifyClients("Enrollment successfull. You can now use your new finger for scanning.");
    updateClientsFingerlist(fingerManager.getFingerListAsHtmlOptionList());
  } else if (finger.enrollResult == EnrollResult::error) {
    notifyClients(String("Enrollment failed. (Code ") + finger.returnCode + ")");
  }
}

void reboot()
{
  notifyClients("System is rebooting now...");
  delay(1000);
    
  mqttClient.disconnect();
  espClient.stop();
  dnsServer.stop();
  webServer.end();
  WiFi.disconnect();
  ESP.restart();
}


// ===== setup() and loop() =====

// Crash counter management (stored in NVS)
int getCrashCount() {
  Preferences prefs;
  prefs.begin("stability", true);
  int count = prefs.getInt("crashCount", 0);
  prefs.end();
  return count;
}

void incrementCrashCount() {
  Preferences prefs;
  prefs.begin("stability", false);
  int count = prefs.getInt("crashCount", 0);
  prefs.putInt("crashCount", count + 1);
  prefs.end();
}

void resetCrashCount() {
  Preferences prefs;
  prefs.begin("stability", false);
  prefs.putInt("crashCount", 0);
  prefs.end();
}

void setup()
{
  Serial.begin(115200);
  while (!Serial);
  delay(100);

  // ===== Crash counter check =====
  incrementCrashCount();  // will be reset after successful boot
  int crashCount = getCrashCount();
  if (crashCount >= MAX_CRASH_COUNT) {
    safeMode = true;
    Serial.println("*** SAFE MODE: Too many consecutive crashes (" + String(crashCount) + "). Only WiFi + WebUI active. ***");
  }

  // ===== Hardware Watchdog =====
  // Initialized later, after all setup is complete

  // initialize GPIOs
  pinMode(doorbellOutputPin, OUTPUT); 
  #ifdef CUSTOM_GPIOS
    pinMode(customOutput1, OUTPUT); 
    pinMode(customOutput2, OUTPUT); 
    pinMode(customInput1, INPUT_PULLDOWN);
    pinMode(customInput2, INPUT_PULLDOWN);
  #endif  

  settingsManager.loadWifiSettings();
  settingsManager.loadAppSettings();

  if (!safeMode) {
    fingerManager.connect();
    fingerManager.setIgnoreTouchRing(settingsManager.getAppSettings().ignoreTouchRing);
    fingerManager.configureLed(
      settingsManager.getAppSettings().ledReadyColor,
      settingsManager.getAppSettings().ledReadyMode,
      settingsManager.getAppSettings().ledScanColor,
      settingsManager.getAppSettings().ledMatchColor,
      settingsManager.getAppSettings().ledNoMatchColor
    );
    
    if (!checkPairingValid())
      notifyClients("Security issue! Pairing with sensor is invalid. This could potentially be an attack! If the sensor is new or has been replaced by you do a (re)pairing in settings page. MQTT messages regarding matching fingerprints will not been sent until pairing is valid again.");
  }

  if (safeMode || fingerManager.isFingerOnSensor() || !settingsManager.isWifiConfigured())
  {
    currentMode = Mode::wificonfig;
    Serial.println("Started WiFi-Config mode");
    if (!safeMode) fingerManager.setLedRingWifiConfig();
    initWiFiAccessPointForConfiguration();
    startWebserver();

  } else {
    Serial.println("Started normal operating mode");
    currentMode = Mode::scan;
    if (initWifi()) {
      // Init NTP after WiFi is connected
      String ntpServer = settingsManager.getAppSettings().ntpServer;
      if (!ntpServer.isEmpty()) {
        long gmtOffset = settingsManager.getAppSettings().gmtOffsetHours * 3600L;
        configTime(gmtOffset, 0, ntpServer.c_str());
        Serial.println("NTP configured: " + ntpServer + " (GMT+" + String(settingsManager.getAppSettings().gmtOffsetHours) + ")");
      }
      startWebserver();
      if (settingsManager.getAppSettings().mqttServer.isEmpty()) {
        mqttConfigValid = false;
        notifyClients("Error: No MQTT Broker is configured! Please go to settings and enter your server URL + user credentials.");
      } else {
        IPAddress mqttServerIp;
        if (WiFi.hostByName(settingsManager.getAppSettings().mqttServer.c_str(), mqttServerIp))
        {
          mqttConfigValid = true;
          Serial.println("IP used for MQTT server: " + mqttServerIp.toString());
          mqttClient.setServer(mqttServerIp, settingsManager.getAppSettings().mqttPort);
          mqttClient.setCallback(mqttCallback);
          // MQTT will connect in loop() via reconnect logic — no blocking delay here
        }
        else {
          mqttConfigValid = false;
          notifyClients("MQTT Server '" + settingsManager.getAppSettings().mqttServer + "' not found. Please check your settings.");
        }
      }
      if (fingerManager.connected)
        fingerManager.setLedRingReady();
      else
        fingerManager.setLedRingError();
    } else {
      fingerManager.setLedRingError();
      shouldReboot = true;
    }
  }

  // If we got here without crashing, boot was successful — reset crash counter
  resetCrashCount();
  Serial.println("Boot successful. Free heap: " + String(ESP.getFreeHeap()) + " bytes");

  // ===== Start Hardware Watchdog AFTER successful boot =====
  esp_task_wdt_init(WDT_TIMEOUT_SEC, true); // true = panic (reboot) on timeout
  esp_task_wdt_add(NULL); // add current task (loopTask) to WDT
  Serial.println("Watchdog started (" + String(WDT_TIMEOUT_SEC) + "s timeout)");
}

void loop()
{
  // Feed the watchdog — proves loop() is alive
  esp_task_wdt_reset();

  if (shouldReboot) {
    reboot();
  }
  
  // Heap monitoring (every 60s)
  unsigned long currentMillis = millis();
  if (currentMillis - lastHeapCheck >= 60000ul) {
    lastHeapCheck = currentMillis;
    uint32_t freeHeap = ESP.getFreeHeap();
    if (freeHeap < 20000) {
      Serial.println("WARNING: Low heap memory: " + String(freeHeap) + " bytes");
      notifyClients("Warning: Low memory (" + String(freeHeap / 1024) + " KB free)");
    }
  }

  // Reconnect handling
  if (currentMode != Mode::wificonfig)
  {
    // reconnect WiFi if down for 30s
    if ((WiFi.status() != WL_CONNECTED) && (currentMillis - wifiReconnectPreviousMillis >= 30000ul)) {
      Serial.println("Reconnecting to WiFi...");
      WiFi.disconnect();
      WiFi.reconnect();
      wifiReconnectPreviousMillis = currentMillis;
    }

    // reconnect mqtt if down
    if (!settingsManager.getAppSettings().mqttServer.isEmpty()) {
      if (!mqttClient.connected() && (currentMillis - mqttReconnectPreviousMillis >= mqttReconnectInterval)) {
        connectMqttClient();
        mqttReconnectPreviousMillis = currentMillis;
      }
      mqttClient.loop();
    }
  }

  // do the actual loop work
  switch (currentMode)
  {
  case Mode::scan:
    if (fingerManager.connected)
      doScan();
    break;
  
  case Mode::enroll:
    doEnroll();
    currentMode = Mode::scan;
    break;
  
  case Mode::wificonfig:
    dnsServer.processNextRequest();
    break;

  case Mode::maintenance:
    break;
  }

  // enter maintenance mode if requested
  if (needMaintenanceMode)
    currentMode = Mode::maintenance;

  #ifdef CUSTOM_GPIOS
    bool i1;
    bool i2;
    i1 = (digitalRead(customInput1) == HIGH);
    i2 = (digitalRead(customInput2) == HIGH);

    String mqttRootTopic = settingsManager.getAppSettings().mqttRootTopic;
    if (i1 != customInput1Value) {
        if (i1)
          mqttClient.publish((String(mqttRootTopic) + "/customInput1").c_str(), "on");      
        else
          mqttClient.publish((String(mqttRootTopic) + "/customInput1").c_str(), "off");      
    }

    if (i2 != customInput2Value) {
        if (i2)
          mqttClient.publish((String(mqttRootTopic) + "/customInput2").c_str(), "on");      
        else
          mqttClient.publish((String(mqttRootTopic) + "/customInput2").c_str(), "off");  
    }

    customInput1Value = i1;
    customInput2Value = i2;
  #endif  
}
