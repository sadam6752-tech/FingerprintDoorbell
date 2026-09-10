#ifndef GLOBAL_H
#define GLOBAL_H

#include <WString.h>

// Forward declarations to avoid circular includes
class FingerprintManager;
class SettingsManager;
class AsyncWebServer;
class AsyncEventSource;
class AsyncWebServerRequest;
class PubSubClient;

// ===== Mode enum =====
enum class Mode { scan, enroll, wificonfig, maintenance };

// ===== Extern declarations for shared globals =====
extern FingerprintManager fingerManager;
extern SettingsManager settingsManager;
extern PubSubClient mqttClient;
extern AsyncWebServer webServer;
extern AsyncEventSource events;

extern Mode currentMode;
extern bool shouldReboot;
extern bool needMaintenanceMode;
extern String enrollId;
extern String enrollName;

// Enroll progress (polled by the ioBroker adapter via /api/status)
//   enrollState: 0=idle, 1=scanning, 2=success, 3=error
//   enrollStep:  current scan step 0..5
//   enrollMessage: last human-readable status line
extern int enrollState;
extern int enrollStep;
extern String enrollMessage;

extern const char* VersionInfo;
extern const int doorbellOutputPin;

extern unsigned long mqttReconnectInterval;
extern bool mqttConfigValid;

#ifdef CUSTOM_GPIOS
  extern const int customOutput1;
  extern const int customOutput2;
  extern const int customInput1;
  extern const int customInput2;
  extern bool customInput1Value;
  extern bool customInput2Value;
#endif

// ===== Shared helper function declarations =====
extern void notifyClients(String message);
extern void updateClientsFingerlist(String fingerlist);
extern String getTimestampString();
extern String getLogMessagesAsHtml();
extern void addLogMessage(const String& message);
extern bool waitForMaintenanceMode();
extern bool authenticateRequest(AsyncWebServerRequest *request);
extern String urlDecode(const String& input);
extern bool checkPairingValid();
extern bool doPairing();

#endif
