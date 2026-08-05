#ifndef WIFIMANAGER_H
#define WIFIMANAGER_H

#include <DNSServer.h>
#include "global.h"

// WiFi Access Point configuration constants
extern const char* WifiConfigSsid;
extern const char* WifiConfigPassword;
extern IPAddress WifiConfigIp;
extern const byte DNS_PORT;
extern DNSServer dnsServer;

bool initWifi();
void initWiFiAccessPointForConfiguration();

#endif
