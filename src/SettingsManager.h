#ifndef SETTINGSMANAGER_H
#define SETTINGSMANAGER_H

#include <Preferences.h>
#include "global.h"

struct WifiSettings {    
    String ssid = "";
    String password = "";
    String hostname = "";
};

struct AppSettings {
    String mqttServer = "";
    String mqttUsername = "";
    String mqttPassword = "";
    int    mqttPort = 1883;
    String mqttRootTopic = "fingerprintDoorbell";
    String ntpServer = "pool.ntp.org";
    int    gmtOffsetHours = 0;
    String httpMatchUrl = "";   // called on fingerprint match, supports {id}, {name}, {confidence}
    String httpRingUrl = "";    // called on ring event (unknown finger)
    // Server mode (ioBroker adapter integration): when true, events go ONLY to the
    // registered server; MQTT and httpMatchUrl/httpRingUrl are skipped.
    bool   serverMode = false;
    String serverHost = "";
    int    serverPort = 8095;
    String serverToken = "";
    String sensorPin = "00000000";
    String sensorPairingCode = "";
    bool   sensorPairingValid = false;
    bool   ignoreTouchRing = false;
    // LED settings: 0=off, 1=red, 2=blue, 3=purple, 4=green, 5=yellow, 6=cyan, 7=white
    uint8_t ledReadyColor = 2;    // blue
    uint8_t ledReadyMode = 2;     // 0=off,1=on,2=breath,3=blink
    uint8_t ledScanColor = 1;     // red
    uint8_t ledMatchColor = 3;    // purple
    uint8_t ledNoMatchColor = 1;  // red (ring event, no match)
    String adminUser = "admin";
    String adminPassword = "";  // empty = no auth (first boot)
};

class SettingsManager {       
  private:
    WifiSettings wifiSettings;
    AppSettings appSettings;

    void saveWifiSettings();
    void saveAppSettings();

  public:
    bool loadWifiSettings();
    bool loadAppSettings();

    WifiSettings getWifiSettings();
    void saveWifiSettings(WifiSettings newSettings);
    
    AppSettings getAppSettings();
    void saveAppSettings(AppSettings newSettings);

    bool isWifiConfigured();

    bool deleteAppSettings();
    bool deleteWifiSettings();

    String generateNewPairingCode();

    bool isAuthConfigured();
    bool checkAuth(const String& user, const String& pass);

};

#endif