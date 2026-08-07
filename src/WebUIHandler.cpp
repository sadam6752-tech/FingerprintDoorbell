#include "WebUIHandler.h"
#include <ESPAsyncWebServer.h>
#include <SPIFFS.h>
#include <ElegantOTA.h>
#include <WiFi.h>
#include <PubSubClient.h>
#include "mbedtls/base64.h"
#include "FingerprintManager.h"
#include "SettingsManager.h"
#include "WiFiManager.h"

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
      return "********";
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
  } else if (var == "GMT_OFFSET") {
    return String(settingsManager.getAppSettings().gmtOffsetHours);
  } else if (var == "TOUCHRING_OFF_SEL") {
    return fingerManager.getIgnoreTouchRing() ? "" : "selected";
  } else if (var == "TOUCHRING_ON_SEL") {
    return fingerManager.getIgnoreTouchRing() ? "selected" : "";
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


void startWebserver(){
  
  // Initialize SPIFFS
  if(!SPIFFS.begin(true)){
    Serial.println("An Error has occurred while mounting SPIFFS");
    // Fallback: register a simple error page so user knows to upload filesystem
    webServer.on("/", HTTP_GET, [](AsyncWebServerRequest *request){
      request->send(200, "text/html", "<html><body><h2>SPIFFS Error</h2><p>Filesystem not available. Please upload via <a href='/update'>/update</a> (Filesystem mode).</p></body></html>");
    });
    webServer.on("/settings", HTTP_GET, [](AsyncWebServerRequest *request){
      request->send(200, "text/html", "<html><body><h2>SPIFFS Error</h2><p>Upload filesystem via <a href='/update'>/update</a></p></body></html>");
    });
    goto register_common_routes;
  }

  // NTP will be configured after WiFi is connected (in main setup)
  
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
        if (request->arg("password").equals("********"))
          settings.password = settingsManager.getWifiSettings().password;
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
        settings.mqttPassword = request->arg("mqtt_password");
        settings.mqttPort = request->arg("mqtt_port").toInt();
        if (settings.mqttPort <= 0 || settings.mqttPort > 65535) settings.mqttPort = 1883;
        settings.mqttRootTopic = request->arg("mqtt_rootTopic");
        settings.ntpServer = request->arg("ntpServer");
        settings.gmtOffsetHours = request->arg("gmtOffset").toInt();
        // Touch ring setting
        String touchRingSetting = request->arg("ignoreTouchRing");
        fingerManager.setIgnoreTouchRing(touchRingSetting == "on");
        // Admin credentials
        String newAdminUser = request->arg("admin_user");
        String newAdminPass = request->arg("admin_password");
        if (!newAdminUser.isEmpty()) settings.adminUser = newAdminUser;
        if (!newAdminPass.isEmpty() && newAdminPass != "********") settings.adminPassword = newAdminPass;
        settingsManager.saveAppSettings(settings);
        // Apply NTP change without reboot
        if (!settings.ntpServer.isEmpty()) {
          long gmtOffset = settings.gmtOffsetHours * 3600L;
          configTime(gmtOffset, 0, settings.ntpServer.c_str());
        }
        request->redirect("/");
        shouldReboot = true; // still reboot to re-init MQTT with new settings
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


    // ===== Add/sync finger name without enrollment =====
    webServer.on("/add-name", HTTP_GET, [](AsyncWebServerRequest *request){
      if (!authenticateRequest(request)) return;
      if (request->hasArg("id") && request->hasArg("name")) {
        int id = request->arg("id").toInt();
        String name = request->arg("name");
        if (id >= 1 && id <= 200 && !name.isEmpty()) {
          fingerManager.renameFinger(id, name);
          notifyClients(String("Name set: #") + id + " = " + name);
        }
      }
      request->redirect("/");
    });

    // ===== Debug endpoint (no auth) — for diagnosing save issues =====
    webServer.on("/debug", HTTP_GET, [](AsyncWebServerRequest *request){
      AppSettings s = settingsManager.getAppSettings();
      String info = "MQTT Server: [" + s.mqttServer + "]\n";
      info += "MQTT User: [" + s.mqttUsername + "]\n";
      info += "MQTT Pass length: " + String(s.mqttPassword.length()) + "\n";
      info += "MQTT Port: " + String(s.mqttPort) + "\n";
      info += "MQTT Topic: [" + s.mqttRootTopic + "]\n";
      info += "NTP: [" + s.ntpServer + "]\n";
      info += "GMT Offset: " + String(s.gmtOffsetHours) + "h\n";
      info += "Admin User: [" + s.adminUser + "]\n";
      info += "Admin Pass length: " + String(s.adminPassword.length()) + "\n";
      info += "Auth configured: " + String(settingsManager.isAuthConfigured() ? "YES" : "NO") + "\n";
      info += "Free heap: " + String(ESP.getFreeHeap()) + "\n";
      info += "Uptime: " + String(millis() / 1000) + "s\n";
      request->send(200, "text/plain", info);
    });

    // ===== Backup Settings (JSON, no fingerprints) =====
    webServer.on("/backup-settings", HTTP_GET, [](AsyncWebServerRequest *request){
      if (!authenticateRequest(request)) return;
      AppSettings s = settingsManager.getAppSettings();
      String json = "{";
      json += "\"mqttServer\":\"" + s.mqttServer + "\",";
      json += "\"mqttUsername\":\"" + s.mqttUsername + "\",";
      json += "\"mqttPassword\":\"" + s.mqttPassword + "\",";
      json += "\"mqttPort\":" + String(s.mqttPort) + ",";
      json += "\"mqttRootTopic\":\"" + s.mqttRootTopic + "\",";
      json += "\"ntpServer\":\"" + s.ntpServer + "\",";
      json += "\"gmtOffsetHours\":" + String(s.gmtOffsetHours) + ",";
      json += "\"adminUser\":\"" + s.adminUser + "\",";
      json += "\"adminPassword\":\"" + s.adminPassword + "\"";
      json += "}";
      AsyncWebServerResponse *response = request->beginResponse(200, "application/json", json);
      response->addHeader("Content-Disposition", "attachment; filename=\"settings-backup.json\"");
      request->send(response);
    });

    // ===== Restore Settings from JSON =====
    webServer.on("/restore-settings", HTTP_POST,
      [](AsyncWebServerRequest *request){
        request->send(200, "text/plain", "Settings restored. Rebooting...");
        shouldReboot = true;
      },
      NULL,
      [](AsyncWebServerRequest *request, uint8_t *data, size_t len, size_t index, size_t total){
        if (!authenticateRequest(request)) return;

        static String bodyBuffer = "";
        if (index == 0) {
          bodyBuffer = "";
          bodyBuffer.reserve(total);
        }
        for (size_t i = 0; i < len; i++) {
          bodyBuffer += (char)data[i];
        }

        if (index + len == total) {
          // Parse JSON settings
          AppSettings settings = settingsManager.getAppSettings();

          auto extractString = [&](const String& key) -> String {
            int idx = bodyBuffer.indexOf("\"" + key + "\":\"");
            if (idx < 0) return "";
            int start = idx + key.length() + 4;
            int end = bodyBuffer.indexOf("\"", start);
            return (end > start) ? bodyBuffer.substring(start, end) : "";
          };
          auto extractInt = [&](const String& key) -> int {
            int idx = bodyBuffer.indexOf("\"" + key + "\":");
            if (idx < 0) return 0;
            return bodyBuffer.substring(idx + key.length() + 3).toInt();
          };

          String val;
          val = extractString("mqttServer"); if (!val.isEmpty()) settings.mqttServer = val;
          val = extractString("mqttUsername"); settings.mqttUsername = val;
          val = extractString("mqttPassword"); if (!val.isEmpty()) settings.mqttPassword = val;
          settings.mqttPort = extractInt("mqttPort"); if (settings.mqttPort <= 0) settings.mqttPort = 1883;
          val = extractString("mqttRootTopic"); if (!val.isEmpty()) settings.mqttRootTopic = val;
          val = extractString("ntpServer"); if (!val.isEmpty()) settings.ntpServer = val;
          settings.gmtOffsetHours = extractInt("gmtOffsetHours");
          val = extractString("adminUser"); if (!val.isEmpty()) settings.adminUser = val;
          val = extractString("adminPassword"); if (!val.isEmpty()) settings.adminPassword = val;

          settingsManager.saveAppSettings(settings);
          bodyBuffer = "";
          notifyClients("Settings restored from backup.");
        }
      }
    );

    webServer.onNotFound([](AsyncWebServerRequest *request){
      request->send(404);
    });

    
  } // end normal operating mode

  register_common_routes:

  // common url callbacks
  webServer.on("/reboot", HTTP_GET, [](AsyncWebServerRequest *request){
    if (!authenticateRequest(request)) return;
    request->redirect("/");
    shouldReboot = true;
  });


  // Enable Over-the-air updates at http://<IPAddress>/update
  ElegantOTA.begin(&webServer, settingsManager.getAppSettings().adminUser.c_str(), settingsManager.getAppSettings().adminPassword.c_str());
  
  // Start server
  webServer.begin();

  notifyClients("System booted successfully!");
}
