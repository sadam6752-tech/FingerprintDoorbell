#include "MQTTManager.h"
#include <Arduino.h>
#include <PubSubClient.h>
#include "FingerprintManager.h"
#include "SettingsManager.h"

void mqttCallback(char* topic, byte* message, unsigned int length) {
  Serial.print("Message arrived on topic: ");
  Serial.print(topic);
  Serial.print(". Message: ");
  String messageTemp;
  
  for (int i = 0; i < (int)length; i++) {
    Serial.print((char)message[i]);
    messageTemp += (char)message[i];
  }
  Serial.println();

  // Check incomming message for interesting topics
  if (String(topic) == String(settingsManager.getAppSettings().mqttRootTopic) + "/ignoreTouchRing") {
    if(messageTemp == "on"){
      fingerManager.setIgnoreTouchRing(true);
      AppSettings s = settingsManager.getAppSettings();
      s.ignoreTouchRing = true;
      settingsManager.saveAppSettings(s);
    }
    else if(messageTemp == "off"){
      fingerManager.setIgnoreTouchRing(false);
      AppSettings s = settingsManager.getAppSettings();
      s.ignoreTouchRing = false;
      settingsManager.saveAppSettings(s);
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
