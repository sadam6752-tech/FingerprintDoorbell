#ifndef MQTTMANAGER_H
#define MQTTMANAGER_H

#include <Arduino.h>
#include "global.h"

void mqttCallback(char* topic, byte* message, unsigned int length);
void connectMqttClient();

#endif
