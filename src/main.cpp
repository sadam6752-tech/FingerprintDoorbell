/***************************************************
  Main of FingerprintDoorbell 
 ****************************************************/

#include <WiFi.h>
#include <DNSServer.h>
#include <time.h>
#include <ESPAsyncWebServer.h>
#include <ElegantOTA.h>
#include <SPIFFS.h>
#include <PubSubClient.h>
#include "mbedtls/base64.h"
#include "FingerprintManager.h"
#include "SettingsManager.h"
#include "global.h"

enum class Mode { scan, enroll, wificonfig, maintenance };

const char* VersionInfo = "0.6";

// ===================================================================================================================
// Caution: below are not the credentials for connecting to your home network, they are for the Access Point mode!!!
// ===================================================================================================================
const char* WifiConfigSsid = "FingerprintDoorbell-Config"; // SSID used for WiFi when in Access Point mode for configuration
const char* WifiConfigPassword = "12345678"; // password used for WiFi when in Access Point mode for configuration. Min. 8 chars needed!
IPAddress   WifiConfigIp(192, 168, 4, 1); // IP of access point in wifi config mode

const long  gmtOffset_sec = 0; // UTC Time
const int   daylightOffset_sec = 0; // UTC Time
const int   doorbellOutputPin = 19; // pin connected to the doorbell (when using hardware connection instead of mqtt to ring the bell)

#ifdef CUSTOM_GPIOS
  const int   customOutput1 = 18; // not used internally, but can be set over MQTT
  const int   customOutput2 = 26; // not used internally, but can be set over MQTT
  const int   customInput1 = 21; // not used internally, but changes are published over MQTT
  const int   customInput2 = 22; // not used internally, but changes are published over MQTT
  bool customInput1Value = false;
  bool customInput2Value = false;
#endif

const int logMessagesCount = 5;
String logMessages[logMessagesCount]; // log messages, 0=most recent log message
bool shouldReboot = false;
unsigned long wifiReconnectPreviousMillis = 0;
unsigned long mqttReconnectPreviousMillis = 0;
unsigned long mqttReconnectInterval = 5000; // start with 5s, grows exponentially

String enrollId;
String enrollName;
Mode currentMode = Mode::scan;

FingerprintManager fingerManager;
SettingsManager settingsManager;
bool needMaintenanceMode = false;

const byte DNS_PORT = 53;
DNSServer dnsServer;
AsyncWebServer webServer(80); // AsyncWebServer  on port 80
AsyncEventSource events("/events"); // event source (Server-Sent events)

WiFiClient espClient;
PubSubClient mqttClient(espClient);
long lastMsg = 0;
char msg[50];
int value = 0;
bool mqttConfigValid = true;


Match lastMatch;

void addLogMessage(const String& message) {
  // shift all messages in array by 1, oldest message will die
  for (int i=logMessagesCount-1; i>0; i--)
    logMessages[i]=logMessages[i-1];
  logMessages[0]=message;
}

String getLogMessagesAsHtml() {
  String html = "";
  for (int i=logMessagesCount-1; i>=0; i--) {
    if (logMessages[i]!="")
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
  strftime(buffer,sizeof(buffer),"%Y-%m-%d %H:%M:%S %Z", &timeinfo);
  String datetime = String(buffer);
  return datetime;
}

/* wait for maintenance mode or timeout 5s */
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

// ===== Authentication helper =====
bool authenticateRequest(AsyncWebServerRequest *request) {
  if (!settingsManager.isAuthConfigured())
    return true;  // no password configured yet, allow access
  if (!request->authenticate(settingsManager.getAppSettings().adminUser.c_str(), 
                              settingsManager.getAppSettings().adminPassword.c_str())) {
    request->requestAuthentication();
    return false;
  }
  return true;
}

// ===== URL decode helper (fix for special chars in MQTT password) =====
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

// Replaces placeholder in HTML pages
String processor(const String& var){
  if(var == "LOGMESSAGES"){
    return getLogMessagesAsHtml();
  } else if (var == "FINGERLIST") {
    return fingerManager.getFingerListAsHtmlOptionList();
  } else if (var == "HOSTNAME") {
    return settingsManager.getWifiSettings().hostname;
  } else if (var == "VERSIONINFO") {
    return VersionInfo;
  } else if (var == "WIFI_SSID") {
    return settingsManager.getWifiSettings().ssid;
  } else if (var == "WIFI_PASSWORD") {
    if (settingsManager.getWifiSettings().password.isEmpty())
      return "";
    else
      return "********"; // for security reasons the wifi password will not left the device once configured
  } else if (var == "MQTT_SERVER") {
    return settingsManager.getAppSettings().mqttServer;
  } else if (var == "MQTT_USERNAME") {
    return settingsManager.getAppSettings().mqttUsername;
  } else if (var == "MQTT_PASSWORD") {
    return settingsManager.getAppSettings().mqttPassword;
  } else if (var == "MQTT_ROOTTOPIC") {
    return settingsManager.getAppSettings().mqttRootTopic;
  } else if (var == "MQTT_PORT") {
    return String(settingsManager.getAppSettings().mqttPort);
  } else if (var == "NTP_SERVER") {
    return settingsManager.getAppSettings().ntpServer;
  } else if (var == "ADMIN_USER") {
    return settingsManager.getAppSettings().adminUser;
  } else if (var == "ADMIN_PASSWORD") {
    if (settingsManager.getAppSettings().adminPassword.isEmpty())
      return "";
    else
      return "********";
  }

  return String();
}


// send LastMessage to websocket clients
void notifyClients(String message) {
  String messageWithTimestamp = "[" + getTimestampString() + "]: " + message;
  Serial.println(messageWithTimestamp);
  addLogMessage(messageWithTimestamp);
  events.send(getLogMessagesAsHtml().c_str(),"message",millis(),1000);
  
  String mqttRootTopic = settingsManager.getAppSettings().mqttRootTopic;
  mqttClient.publish((String(mqttRootTopic) + "/lastLogMessage").c_str(), message.c_str());
}

void updateClientsFingerlist(String fingerlist) {
  Serial.println("New fingerlist was sent to clients");
  events.send(fingerlist.c_str(),"fingerlist",millis(),1000);
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
       // first boot, do pairing automatically so the user does not have to do this manually
       return doPairing();
     } else {
      Serial.println("Pairing has been invalidated previously.");   
      return false;
     }
   }

  String actualSensorPairingCode = fingerManager.getPairingCode();
  //Serial.println("Awaited pairing code: " + settings.sensorPairingCode);
  //Serial.println("Actual pairing code: " + actualSensorPairingCode);

  if (actualSensorPairingCode.equals(settings.sensorPairingCode))
    return true;
  else {
    if (!actualSensorPairingCode.isEmpty()) { 
      // An empty code means there was a communication problem. So we don't have a valid code, but maybe next read will succeed and we get one again.
      // But here we just got an non-empty pairing code that was different to the awaited one. So don't expect that will change in future until repairing was done.
      // -> invalidate pairing for security reasons
      AppSettings settings = settingsManager.getAppSettings();
      settings.sensorPairingValid = false;
      settingsManager.saveAppSettings(settings);
    }
    return false;
  }
}


bool initWifi() {
  // Connect to Wi-Fi
  WifiSettings wifiSettings = settingsManager.getWifiSettings();
  WiFi.mode(WIFI_STA);
  WiFi.config(INADDR_NONE, INADDR_NONE, INADDR_NONE, INADDR_NONE);
  WiFi.setHostname(wifiSettings.hostname.c_str()); //define hostname
  WiFi.begin(wifiSettings.ssid.c_str(), wifiSettings.password.c_str());
  int counter = 0;
  while (WiFi.status() != WL_CONNECTED) {
    delay(1000);
    Serial.println("Waiting for WiFi connection...");
    counter++;
    if (counter > 30)
      return false;
  }
  Serial.println("Connected!");

  // Print ESP32 Local IP Address
  Serial.println(WiFi.localIP());

  return true;
}

void initWiFiAccessPointForConfiguration() {
  WiFi.softAPConfig(WifiConfigIp, WifiConfigIp, IPAddress(255, 255, 255, 0));
  WiFi.softAP(WifiConfigSsid, WifiConfigPassword);

  // if DNSServer is started with "*" for domain name, it will reply with
  // provided IP to all DNS request
  dnsServer.start(DNS_PORT, "*", WifiConfigIp);

  Serial.print("AP IP address: ");
  Serial.println(WifiConfigIp); 
}


void startWebserver(){
  
  // Initialize SPIFFS
  if(!SPIFFS.begin(true)){
    Serial.println("An Error has occurred while mounting SPIFFS");
    return;
  }

  // Init time by NTP Client
  configTime(gmtOffset_sec, daylightOffset_sec, settingsManager.getAppSettings().ntpServer.c_str());
  
  // webserver for normal operating or wifi config?
  if (currentMode == Mode::wificonfig)
  {
    // =================
    // WiFi config mode
    // =================

    webServer.on("/", HTTP_GET, [](AsyncWebServerRequest *request){
      request->send(SPIFFS, "/wificonfig.html", String(), false, processor);
    });

    webServer.on("/save", HTTP_GET, [](AsyncWebServerRequest *request){
      if(request->hasArg("hostname"))
      {
        Serial.println("Save wifi config");
        WifiSettings settings = settingsManager.getWifiSettings();
        settings.hostname = request->arg("hostname");
        settings.ssid = request->arg("ssid");
        if (request->arg("password").equals("********")) // password is replaced by wildcards when given to the browser, so if the user didn't changed it, don't save it
          settings.password = settingsManager.getWifiSettings().password; // use the old, already saved, one
        else
          settings.password = request->arg("password");
        settingsManager.saveWifiSettings(settings);
        shouldReboot = true;
      }
      request->redirect("/");
    });


    webServer.onNotFound([](AsyncWebServerRequest *request){
      AsyncResponseStream *response = request->beginResponseStream("text/html");
      response->printf("<!DOCTYPE html><html><head><title>FingerprintDoorbell</title><meta http-equiv=\"refresh\" content=\"0; url=http://%s\" /></head><body>", WiFi.softAPIP().toString().c_str());
      response->printf("<p>Please configure your WiFi settings <a href='http://%s'>here</a> to connect FingerprintDoorbell to your home network.</p>", WiFi.softAPIP().toString().c_str());
      response->print("</body></html>");
      request->send(response);
    });

  }
  else
  {
    // =======================
    // normal operating mode
    // =======================
    events.onConnect([](AsyncEventSourceClient *client){
      if(client->lastId()){
        Serial.printf("Client reconnected! Last message ID it got was: %u\n", client->lastId());
      }
      //send event with message "ready", id current millis
      // and set reconnect delay to 1 second
      client->send(getLogMessagesAsHtml().c_str(),"message",millis(),1000);
    });
    webServer.addHandler(&events);

    
    // Route for root / web page
    webServer.on("/", HTTP_GET, [](AsyncWebServerRequest *request){
      if (!authenticateRequest(request)) return;
      request->send(SPIFFS, "/index.html", String(), false, processor);
    });

    webServer.on("/enroll", HTTP_GET, [](AsyncWebServerRequest *request){
      if (!authenticateRequest(request)) return;
      if(request->hasArg("startEnrollment"))
      {
        enrollId = request->arg("newFingerprintId");
        enrollName = request->arg("newFingerprintName");
        currentMode = Mode::enroll;
      }
      request->redirect("/");
    });

    webServer.on("/editFingerprints", HTTP_GET, [](AsyncWebServerRequest *request){
      if (!authenticateRequest(request)) return;
      if(request->hasArg("selectedFingerprint"))
      {
        if(request->hasArg("btnDelete"))
        {
          int id = request->arg("selectedFingerprint").toInt();
          waitForMaintenanceMode();
          fingerManager.deleteFinger(id);
          currentMode = Mode::scan;
        }
        else if (request->hasArg("btnRename"))
        {
          int id = request->arg("selectedFingerprint").toInt();
          String newName = request->arg("renameNewName");
          fingerManager.renameFinger(id, newName);
        }
      }
      request->redirect("/");  
    });

    webServer.on("/settings", HTTP_GET, [](AsyncWebServerRequest *request){
      if (!authenticateRequest(request)) return;
      if(request->hasArg("btnSaveSettings"))
      {
        Serial.println("Save settings");
        AppSettings settings = settingsManager.getAppSettings();
        settings.mqttServer = request->arg("mqtt_server");
        settings.mqttUsername = request->arg("mqtt_username");
        settings.mqttPassword = urlDecode(request->arg("mqtt_password"));
        settings.mqttPort = request->arg("mqtt_port").toInt();
        if (settings.mqttPort <= 0 || settings.mqttPort > 65535) settings.mqttPort = 1883;
        settings.mqttRootTopic = request->arg("mqtt_rootTopic");
        settings.ntpServer = request->arg("ntpServer");
        // Admin credentials
        String newAdminUser = request->arg("admin_user");
        String newAdminPass = request->arg("admin_password");
        if (!newAdminUser.isEmpty()) settings.adminUser = newAdminUser;
        if (!newAdminPass.isEmpty() && newAdminPass != "********") settings.adminPassword = newAdminPass;
        settingsManager.saveAppSettings(settings);
        request->redirect("/");  
        shouldReboot = true;
      } else {
        request->send(SPIFFS, "/settings.html", String(), false, processor);
      }
    });


    webServer.on("/pairing", HTTP_GET, [](AsyncWebServerRequest *request){
      if (!authenticateRequest(request)) return;
      if(request->hasArg("btnDoPairing"))
      {
        Serial.println("Do (re)pairing");
        doPairing();
        request->redirect("/");  
      } else {
        request->send(SPIFFS, "/settings.html", String(), false, processor);
      }
    });



    webServer.on("/factoryReset", HTTP_GET, [](AsyncWebServerRequest *request){
      if (!authenticateRequest(request)) return;
      if(request->hasArg("btnFactoryReset"))
      {
        notifyClients("Factory reset initiated...");
        
        if (!fingerManager.deleteAll())
          notifyClients("Finger database could not be deleted.");
        
        if (!settingsManager.deleteAppSettings())
          notifyClients("App settings could not be deleted.");

        if (!settingsManager.deleteWifiSettings())
          notifyClients("Wifi settings could not be deleted.");
        
        request->redirect("/");  
        shouldReboot = true;
      } else {
        request->send(SPIFFS, "/settings.html", String(), false, processor);
      }
    });


    webServer.on("/deleteAllFingerprints", HTTP_GET, [](AsyncWebServerRequest *request){
      if (!authenticateRequest(request)) return;
      if(request->hasArg("btnDeleteAllFingerprints"))
      {
        notifyClients("Deleting all fingerprints...");
        
        if (!fingerManager.deleteAll())
          notifyClients("Finger database could not be deleted.");
        
        request->redirect("/");  
        
      } else {
        request->send(SPIFFS, "/settings.html", String(), false, processor);
      }
    });


    // ===== Backup: download fingerprints as JSON =====
    webServer.on("/backup", HTTP_GET, [](AsyncWebServerRequest *request){
      if (!authenticateRequest(request)) return;
      notifyClients("Starting fingerprint backup...");
      waitForMaintenanceMode();
      String json = fingerManager.exportFingerprintsToJson();
      currentMode = Mode::scan;
      notifyClients("Backup completed.");
      AsyncWebServerResponse *response = request->beginResponse(200, "application/json", json);
      response->addHeader("Content-Disposition", "attachment; filename=\"fingerprints-backup.json\"");
      request->send(response);
    });

    // ===== Restore: upload fingerprints JSON =====
    webServer.on("/restore", HTTP_POST, 
      // onRequest handler (called after body is received)
      [](AsyncWebServerRequest *request){
        request->redirect("/");
      },
      // onUpload handler (not used)
      NULL,
      // onBody handler (receives POST body)
      [](AsyncWebServerRequest *request, uint8_t *data, size_t len, size_t index, size_t total){
        if (!authenticateRequest(request)) return;
        
        // Accumulate body data
        static String bodyBuffer = "";
        if (index == 0) {
          bodyBuffer = "";
          bodyBuffer.reserve(total);
        }
        for (size_t i = 0; i < len; i++) {
          bodyBuffer += (char)data[i];
        }
        
        // When complete, parse and import
        if (index + len == total) {
          notifyClients("Starting fingerprint restore...");
          waitForMaintenanceMode();
          
          int imported = 0;
          int failed = 0;
          
          // Simple JSON parser for our known format
          // Format: [{"id":1,"name":"Alex","size":512,"template":"base64..."},...]
          int searchPos = 0;
          while (true) {
            int objStart = bodyBuffer.indexOf('{', searchPos);
            if (objStart < 0) break;
            int objEnd = bodyBuffer.indexOf('}', objStart);
            if (objEnd < 0) break;
            
            String obj = bodyBuffer.substring(objStart, objEnd + 1);
            searchPos = objEnd + 1;
            
            // Extract id
            int idIdx = obj.indexOf("\"id\":");
            if (idIdx < 0) continue;
            int id = obj.substring(idIdx + 5).toInt();
            
            // Extract name
            int nameIdx = obj.indexOf("\"name\":\"");
            if (nameIdx < 0) continue;
            int nameStart = nameIdx + 8;
            int nameEnd = obj.indexOf("\"", nameStart);
            String name = obj.substring(nameStart, nameEnd);
            
            // Extract size
            int sizeIdx = obj.indexOf("\"size\":");
            int templateSize = 0;
            if (sizeIdx >= 0) {
              templateSize = obj.substring(sizeIdx + 7).toInt();
            }
            
            // Extract template (base64)
            int tplIdx = obj.indexOf("\"template\":\"");
            if (tplIdx < 0) continue;
            int tplStart = tplIdx + 12;
            int tplEnd = obj.indexOf("\"", tplStart);
            String b64Template = obj.substring(tplStart, tplEnd);
            
            // Decode base64
            size_t decodedLen = 0;
            mbedtls_base64_decode(NULL, 0, &decodedLen, (const unsigned char*)b64Template.c_str(), b64Template.length());
            uint8_t* templateData = (uint8_t*)malloc(decodedLen);
            if (!templateData) {
              failed++;
              continue;
            }
            size_t actualLen = 0;
            int ret = mbedtls_base64_decode(templateData, decodedLen, &actualLen, (const unsigned char*)b64Template.c_str(), b64Template.length());
            if (ret != 0) {
              free(templateData);
              failed++;
              continue;
            }
            if (templateSize == 0) templateSize = actualLen;
            
            // Import
            if (fingerManager.importFingerprintFromTemplate(id, name, templateData, templateSize)) {
              imported++;
            } else {
              failed++;
            }
            free(templateData);
          }
          
          currentMode = Mode::scan;
          bodyBuffer = "";
          notifyClients(String("Restore completed: ") + imported + " imported, " + failed + " failed.");
          updateClientsFingerlist(fingerManager.getFingerListAsHtmlOptionList());
        }
      }
    );


    webServer.onNotFound([](AsyncWebServerRequest *request){
      request->send(404);
    });

    
  } // end normal operating mode


  // common url callbacks
  webServer.on("/reboot", HTTP_GET, [](AsyncWebServerRequest *request){
    if (!authenticateRequest(request)) return;
    request->redirect("/");
    shouldReboot = true;
  });

  webServer.on("/bootstrap.min.css", HTTP_GET, [](AsyncWebServerRequest *request){
    request->send(SPIFFS, "/bootstrap.min.css", "text/css");
  });


  // Enable Over-the-air updates at http://<IPAddress>/update
  ElegantOTA.begin(&webServer, settingsManager.getAppSettings().adminUser.c_str(), settingsManager.getAppSettings().adminPassword.c_str());
  
  // Start server
  webServer.begin();

  notifyClients("System booted successfully!");

}


void mqttCallback(char* topic, byte* message, unsigned int length) {
  Serial.print("Message arrived on topic: ");
  Serial.print(topic);
  Serial.print(". Message: ");
  String messageTemp;
  
  for (int i = 0; i < length; i++) {
    Serial.print((char)message[i]);
    messageTemp += (char)message[i];
  }
  Serial.println();

  // Check incomming message for interesting topics
  if (String(topic) == String(settingsManager.getAppSettings().mqttRootTopic) + "/ignoreTouchRing") {
    if(messageTemp == "on"){
      fingerManager.setIgnoreTouchRing(true);
    }
    else if(messageTemp == "off"){
      fingerManager.setIgnoreTouchRing(false);
    }
  }

  if (String(topic) == String(settingsManager.getAppSettings().mqttRootTopic) + "/reboot") {
    if(messageTemp == "on"){
      shouldReboot = true;
    }
  }

  #ifdef CUSTOM_GPIOS
    if (String(topic) == String(settingsManager.getAppSettings().mqttRootTopic) + "/customOutput1") {
      if(messageTemp == "on"){
        digitalWrite(customOutput1, HIGH); 
      }
      else if(messageTemp == "off"){
        digitalWrite(customOutput1, LOW); 
      }
    }
    if (String(topic) == String(settingsManager.getAppSettings().mqttRootTopic) + "/customOutput2") {
      if(messageTemp == "on"){
        digitalWrite(customOutput2, HIGH); 
      }
      else if(messageTemp == "off"){
        digitalWrite(customOutput2, LOW); 
      }
    }
  #endif  

}

void connectMqttClient() {
  if (!mqttClient.connected() && mqttConfigValid) {
    Serial.print("(Re)connect to MQTT broker...");
    // Attempt to connect
    bool connectResult;
    
    // connect with or without authentication
    String mqttRootTopic = settingsManager.getAppSettings().mqttRootTopic;
    String statusTopic = mqttRootTopic + "/status";
    String lastWillMessage = "offline";
    if (settingsManager.getAppSettings().mqttUsername.isEmpty() || settingsManager.getAppSettings().mqttPassword.isEmpty())
      connectResult = mqttClient.connect(settingsManager.getWifiSettings().hostname.c_str(), statusTopic.c_str(), 1, true, lastWillMessage.c_str());
    else
      connectResult = mqttClient.connect(settingsManager.getWifiSettings().hostname.c_str(), settingsManager.getAppSettings().mqttUsername.c_str(), settingsManager.getAppSettings().mqttPassword.c_str(), statusTopic.c_str(), 1, true, lastWillMessage.c_str());

    if (connectResult) {
      // success
      Serial.println("connected");
      mqttReconnectInterval = 5000; // reset backoff on success
      // Publish online status (retained)
      mqttClient.publish(statusTopic.c_str(), "online", true);
      // Subscribe
      mqttClient.subscribe((mqttRootTopic + "/ignoreTouchRing").c_str(), 1);
      mqttClient.subscribe((mqttRootTopic + "/reboot").c_str(), 1);
      #ifdef CUSTOM_GPIOS
        mqttClient.subscribe((mqttRootTopic + "/customOutput1").c_str(), 1);
        mqttClient.subscribe((mqttRootTopic + "/customOutput2").c_str(), 1);
      #endif

    } else {
      if (mqttClient.state() == 4 || mqttClient.state() == 5) {
        mqttConfigValid = false;
        notifyClients("Failed to connect to MQTT Server: bad credentials or not authorized. Will not try again, please check your settings.");
      } else {
        notifyClients(String("Failed to connect to MQTT Server, rc=") + mqttClient.state() + ", try again in " + (mqttReconnectInterval/1000) + " seconds");
        // exponential backoff: 5s, 10s, 20s, 40s, max 60s
        mqttReconnectInterval = min(mqttReconnectInterval * 2, 60000ul);
      }
    }
  }
}


void doScan()
{
  Match match = fingerManager.scanFingerprint();
  String mqttRootTopic = settingsManager.getAppSettings().mqttRootTopic;
  switch(match.scanResult)
  {
    case ScanResult::noFinger:
      // standard case, occurs every iteration when no finger touchs the sensor
      if (match.scanResult != lastMatch.scanResult) {
        Serial.println("no finger");
        mqttClient.publish((String(mqttRootTopic) + "/ring").c_str(), "off");
        mqttClient.publish((String(mqttRootTopic) + "/matchId").c_str(), "-1");
        mqttClient.publish((String(mqttRootTopic) + "/matchName").c_str(), "");
        mqttClient.publish((String(mqttRootTopic) + "/matchConfidence").c_str(), "-1");
      }
      break; 
    case ScanResult::matchFound:
      notifyClients( String("Match Found: ") + match.matchId + " - " + match.matchName  + " with confidence of " + match.matchConfidence );
      if (checkPairingValid()) {
        mqttClient.publish((String(mqttRootTopic) + "/ring").c_str(), "off");
        mqttClient.publish((String(mqttRootTopic) + "/matchId").c_str(), String(match.matchId).c_str());
        mqttClient.publish((String(mqttRootTopic) + "/matchName").c_str(), match.matchName.c_str());
        mqttClient.publish((String(mqttRootTopic) + "/matchConfidence").c_str(), String(match.matchConfidence).c_str());
        Serial.println("MQTT message sent: Open the door!");
      } else {
        notifyClients("Security issue! Match was not sent by MQTT because of invalid sensor pairing! This could potentially be an attack! If the sensor is new or has been replaced by you do a (re)pairing in settings page.");
      }
      delay(3000); // wait some time before next scan to let the LED blink
      break;
    case ScanResult::noMatchFound:
      notifyClients(String("No Match Found (Code ") + match.returnCode + ")");
      if (match.scanResult != lastMatch.scanResult) {
        digitalWrite(doorbellOutputPin, HIGH);
        mqttClient.publish((String(mqttRootTopic) + "/ring").c_str(), "on");
        mqttClient.publish((String(mqttRootTopic) + "/matchId").c_str(), "-1");
        mqttClient.publish((String(mqttRootTopic) + "/matchName").c_str(), "");
        mqttClient.publish((String(mqttRootTopic) + "/matchConfidence").c_str(), "-1");
        Serial.println("MQTT message sent: ring the bell!");
        delay(1000);
        digitalWrite(doorbellOutputPin, LOW); 
      } else {
        delay(1000); // wait some time before next scan to let the LED blink
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
  }  else if (finger.enrollResult == EnrollResult::error) {
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


void setup()
{
  // open serial monitor for debug infos
  Serial.begin(115200);
  while (!Serial);  // For Yun/Leo/Micro/Zero/...
  delay(100);

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

  fingerManager.connect();
  
  if (!checkPairingValid())
    notifyClients("Security issue! Pairing with sensor is invalid. This could potentially be an attack! If the sensor is new or has been replaced by you do a (re)pairing in settings page. MQTT messages regarding matching fingerprints will not been sent until pairing is valid again.");

  if (fingerManager.isFingerOnSensor() || !settingsManager.isWifiConfigured())
  {
    // ring touched during startup or no wifi settings stored -> wifi config mode
    currentMode = Mode::wificonfig;
    Serial.println("Started WiFi-Config mode");
    fingerManager.setLedRingWifiConfig();
    initWiFiAccessPointForConfiguration();
    startWebserver();

  } else {
    Serial.println("Started normal operating mode");
    currentMode = Mode::scan;
    if (initWifi()) {
      startWebserver();
      if (settingsManager.getAppSettings().mqttServer.isEmpty()) {
        mqttConfigValid = false;
        notifyClients("Error: No MQTT Broker is configured! Please go to settings and enter your server URL + user credentials.");
      } else {
        delay(5000);
        IPAddress mqttServerIp;
        if (WiFi.hostByName(settingsManager.getAppSettings().mqttServer.c_str(), mqttServerIp))
        {
          mqttConfigValid = true;
          Serial.println("IP used for MQTT server: " + mqttServerIp.toString());
          mqttClient.setServer(mqttServerIp, settingsManager.getAppSettings().mqttPort);
          mqttClient.setCallback(mqttCallback);
          connectMqttClient();
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
    }  else {
      fingerManager.setLedRingError();
      shouldReboot = true;
    }

  }
  
}

void loop()
{
  // shouldReboot flag for supporting reboot through webui
  if (shouldReboot) {
    reboot();
  }
  
  // Reconnect handling
  if (currentMode != Mode::wificonfig)
  {
    unsigned long currentMillis = millis();
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
    currentMode = Mode::scan; // switch back to scan mode after enrollment is done
    break;
  
  case Mode::wificonfig:
    dnsServer.processNextRequest(); // used for captive portal redirect
    break;

  case Mode::maintenance:
    // do nothing, give webserver exclusive access to sensor (not thread-safe for concurrent calls)
    break;

  }

  // enter maintenance mode (no continous scanning) if requested
  if (needMaintenanceMode)
    currentMode = Mode::maintenance;

  #ifdef CUSTOM_GPIOS
    // read custom inputs and publish by MQTT
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

