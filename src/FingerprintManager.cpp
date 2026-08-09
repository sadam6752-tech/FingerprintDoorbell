#include "FingerprintManager.h"
#include "global.h"

#include <Adafruit_Fingerprint.h>
#include <base64.h>
#include "mbedtls/base64.h"

bool FingerprintManager::connect() {
  
    // initialize input pins
    pinMode(touchRingPin, INPUT_PULLDOWN);

    Serial.println("\n\nAdafruit finger detect test");

    // set the data rate for the sensor serial port
    finger.begin(57600);
    delay(50);
    if (finger.verifyPassword()) {
        Serial.println("Found fingerprint sensor!");
    } else {
        delay(5000); // wait a bit longer for sensor to start before 2nd try (usually after a OTA-Update the esp32 is faster with startup than the fingerprint sensor)
        if (finger.verifyPassword()) { 
          Serial.println("Found fingerprint sensor!");
        } else {
          Serial.println("Did not find fingerprint sensor :(");
          connected = false;
          return connected;
        }
    }
    finger.LEDcontrol(FINGERPRINT_LED_FLASHING, 25, FINGERPRINT_LED_BLUE, 0); // sensor connected signal

    Serial.println(F("Reading sensor parameters"));
    finger.getParameters();
    Serial.print(F("Status: 0x")); Serial.println(finger.status_reg, HEX);
    Serial.print(F("Sys ID: 0x")); Serial.println(finger.system_id, HEX);
    Serial.print(F("Capacity: ")); Serial.println(finger.capacity);
    Serial.print(F("Security level: ")); Serial.println(finger.security_level);
    Serial.print(F("Device address: ")); Serial.println(finger.device_addr, HEX);
    Serial.print(F("Packet len: ")); Serial.println(finger.packet_len);
    Serial.print(F("Baud rate: ")); Serial.println(finger.baud_rate);

    finger.getTemplateCount();
    Serial.print("Sensor contains "); Serial.print(finger.templateCount); Serial.println(" templates");

    loadFingerListFromPrefs();

    connected = true;
    return connected;

    //updateTouchState(false);
}

void FingerprintManager::updateTouchState(bool touched)
{
  if ((touched != lastTouchState) || (ignoreTouchRing != lastIgnoreTouchRing)) {
      // check if sensor or ring is touched
      if (touched) {
        // turn touch indicator on:
        setLedRingScan();
      } else {
        // turn touch indicator off:
        setLedRingReady();
     }
  }
  lastTouchState = touched;
  lastIgnoreTouchRing = ignoreTouchRing;
  
}


Match FingerprintManager::scanFingerprint() {
  
  Match match;
  match.scanResult = ScanResult::error;

  if (!connected) {
      return match;
  }


  // finger detection by capacitive touchRing state (increased sensitivy but error prone due to rain)
  bool ringTouched = false;
  if (!ignoreTouchRing)
  {
    if (isRingTouched())
      ringTouched = true;
    if (ringTouched || lastTouchState) { 
        updateTouchState(true);
        //Serial.println("touched");
    } else {
        updateTouchState(false);
        match.scanResult = ScanResult::noFinger;
        return match;
    }

  }
  

  bool doAnotherScan = true;
  int scanPass = 0;
  while (doAnotherScan)
  {
    doAnotherScan = false;
    scanPass++;

    ///////////////////////////////////////////////////////////
    // STEP 1: Get Image from Sensor
    ///////////////////////////////////////////////////////////
    bool doImaging = true;
    int imagingPass = 0;
    while (doImaging)
    {
      doImaging = false;
      imagingPass++;
      //Serial.println(String("Get Image try ") + imagingPass);
      match.returnCode = finger.getImage();
      switch (match.returnCode) {
        case FINGERPRINT_OK:
          // Important: do net set touch state to true yet! Reason:
          // - if touchRing is NOT ignored, updateTouchState(true) was already called a few lines up, ring is already flashing red
          // - if touchRing IS ignored, wait for next step because image still can be "too messy" (=raindrop on sensor), and we don't want to flash red in this case
          //updateTouchState(true);
          //Serial.println("Image taken");
          break;
        case FINGERPRINT_NOFINGER:
        case FINGERPRINT_PACKETRECIEVEERR: // occurs from time to time, handle it like a "nofinger detected but touched" situation
          if (ringTouched) {
            // no finger on sensor but ring was touched -> ring event
            //Serial.println("ring touched");
            updateTouchState(true);
            if (imagingPass < 15) // up to x image passes in a row are taken after touch ring was touched until noFinger will raise a noMatchFound event
            {
              doImaging = true; // scan another image
              //delay(50);
              break;
            } else {
              //Serial.println("15 times no image after touching ring");
              match.scanResult = ScanResult::noMatchFound;
              return match;
            }
          } else  {
            if (ignoreTouchRing && scanPass > 1) {
              // the scan(s) in last iteration(s) have not found any match, now the finger was released (=no finger) -> return "no match" as result
              match.scanResult = ScanResult::noMatchFound;
            } else {
              match.scanResult = ScanResult::noFinger;
              updateTouchState(false);
            }
            return match;
          }
        case FINGERPRINT_IMAGEFAIL:
          Serial.println("Imaging error");
          updateTouchState(true);
          return match;
        default:
          Serial.println("Unknown error");
          return match;
      }
    
    }

    ///////////////////////////////////////////////////////////
    // STEP 2: Convert Image to feature map
    ///////////////////////////////////////////////////////////
    match.returnCode = finger.image2Tz();
    switch (match.returnCode) {
      case FINGERPRINT_OK:
        //Serial.println("Image converted");
        updateTouchState(true);
        break;
      case FINGERPRINT_IMAGEMESS:
        Serial.println("Image too messy");
        return match;
      case FINGERPRINT_PACKETRECIEVEERR:
        Serial.println("Communication error");
        return match;
      case FINGERPRINT_FEATUREFAIL:
        Serial.println("Could not find fingerprint features");
        return match;
      case FINGERPRINT_INVALIDIMAGE:
        Serial.println("Could not find fingerprint features");
        return match;
      default:
        Serial.println("Unknown error");
        return match;
    }

    ///////////////////////////////////////////////////////////
    // STEP 3: Search DB for matching features
    ///////////////////////////////////////////////////////////
    match.returnCode = finger.fingerSearch();
    if (match.returnCode == FINGERPRINT_OK) {
        // found a match!
        setLedRingMatch();
        
        match.scanResult = ScanResult::matchFound;
        match.matchId = finger.fingerID;
        match.matchConfidence = finger.confidence;
        match.matchName = fingerList[finger.fingerID];
      
    } else if (match.returnCode == FINGERPRINT_PACKETRECIEVEERR) {
        Serial.println("Communication error");

    } else if (match.returnCode == FINGERPRINT_NOTFOUND) {
        Serial.println(String("Did not find a match. (Scan #") + scanPass + String(" of 5)"));
        match.scanResult = ScanResult::noMatchFound;
        if (scanPass < 5) // max 5 Scans until no match found is given back as result
          doAnotherScan = true;

    } else {
        Serial.println("Unknown error");
    }

  } //while

  return match;

}



// Preferences
void FingerprintManager::loadFingerListFromPrefs() {
  Preferences preferences;
  preferences.begin("fingerList", true); 
  int counter = 0;
  for (int i=1; i<=200; i++) {
    String key = String(i);
    if (preferences.isKey(key.c_str())) {
      fingerList[i] = preferences.getString(key.c_str(), String("@empty"));
      counter++;
    }
    else
      fingerList[i] = String("@empty");
  }
  Serial.println(String(counter) + " fingers loaded from preferences.");
  if (counter != finger.templateCount)
    notifyClients(String("Warning: Fingerprint count mismatch! ") + finger.templateCount + " fingerprints stored on sensor, but we are aware of " + counter + " fingerprints.");
  preferences.end();
}


// Add/Enroll fingerprint
NewFinger FingerprintManager::enrollFinger(int id, String name) {

  NewFinger newFinger;
  newFinger.enrollResult = EnrollResult::error;

  lastTouchState = true; // after enrollment, scan mode kicks in again. Force update of the ring light back to normal on first iteration of scan mode.

  
  notifyClients(String("Enrollment for id #") + id + " started. We need to scan your finger 5 times until enrollment is completed.");

  
  // Repeat n times to get better resulting templates (as stated in R503 documentation up to 6 combined image samples possible, but I got an communication error when trying more than 5 samples, so dont go >5)
  for (int nTimes=1; nTimes<=5; nTimes++)
  {
      notifyClients(String("Take #" + String(nTimes))+ " (place your finger on the sensor until led ring stops flashing, then remove it).");

      if (nTimes != 1) // not on first run
      {
        //delay(2000);
        newFinger.returnCode = 0xFF;
        while (newFinger.returnCode != FINGERPRINT_NOFINGER) {
          newFinger.returnCode = finger.getImage();
        }
      }
      
      Serial.print("Taking image sample "); Serial.print(nTimes); Serial.print(": ");
      finger.LEDcontrol(FINGERPRINT_LED_FLASHING, 25, FINGERPRINT_LED_PURPLE, 0);
      newFinger.returnCode = 0xFF;
      while (newFinger.returnCode != FINGERPRINT_OK) {
        newFinger.returnCode = finger.getImage();
        switch (newFinger.returnCode) {
        case FINGERPRINT_OK:
          Serial.print("taken, ");
          break;
        case FINGERPRINT_NOFINGER:
          break;
        case FINGERPRINT_PACKETRECIEVEERR:
          Serial.print("Communication error, ");
          break;
        case FINGERPRINT_IMAGEFAIL:
          Serial.print("Imaging error, ");
          break;
        default:
          Serial.print("Unknown error, ");
          break;
        }
      }
    
      // OK success!
    
      newFinger.returnCode = finger.image2Tz(nTimes);
      switch (newFinger.returnCode) {
        case FINGERPRINT_OK:
          Serial.print("converted");
          break;
        case FINGERPRINT_IMAGEMESS:
          Serial.print("too messy");
          return newFinger;
        case FINGERPRINT_PACKETRECIEVEERR:
          Serial.print("Communication error");
          return newFinger;
        case FINGERPRINT_FEATUREFAIL:
          Serial.print("Could not find fingerprint features");
          return newFinger;
        case FINGERPRINT_INVALIDIMAGE:
          Serial.print("Could not find fingerprint features");
          return newFinger;
        default:
          Serial.print("Unknown error");
          return newFinger;
      }
      finger.LEDcontrol(FINGERPRINT_LED_ON, 0, FINGERPRINT_LED_PURPLE);

  }

  

  // OK converted!
  Serial.println();
  Serial.print("Creating model for #");  Serial.println(id);

  newFinger.returnCode = finger.createModel();
  if (newFinger.returnCode == FINGERPRINT_OK) {
    Serial.println("Prints matched!");
  } else if (newFinger.returnCode == FINGERPRINT_PACKETRECIEVEERR) {
    Serial.println("Communication error");
    return newFinger;
  } else if (newFinger.returnCode == FINGERPRINT_ENROLLMISMATCH) {
    Serial.println("Fingerprints did not match");
    return newFinger;
  } else {
    Serial.println("Unknown error");
    return newFinger;
  }

  Serial.print("ID "); Serial.println(id);
  newFinger.returnCode = finger.storeModel(id);
  if (newFinger.returnCode == FINGERPRINT_OK) {
    Serial.println("Stored!");
    newFinger.enrollResult = EnrollResult::ok;
    // save to prefs
    fingerList[id] = name;
    Preferences preferences;
    preferences.begin("fingerList", false); 
    preferences.putString(String(id).c_str(), name);
    preferences.end();

  } else if (newFinger.returnCode == FINGERPRINT_PACKETRECIEVEERR) {
    Serial.println("Communication error");
    return newFinger;
  } else if (newFinger.returnCode == FINGERPRINT_BADLOCATION) {
    Serial.println("Could not store in that location");
    return newFinger;
  } else if (newFinger.returnCode == FINGERPRINT_FLASHERR) {
    Serial.println("Error writing to flash");
    return newFinger;
  } else {
    Serial.println("Unknown error");
    return newFinger;
  }

  //finger.LEDcontrol(FINGERPRINT_LED_OFF, 0, FINGERPRINT_LED_RED);

  return newFinger;

}


void FingerprintManager::deleteFinger(int id) {
          
  if ((id > 0) && (id <= 200)) {
    int8_t result = finger.deleteModel(id);
    if (result != FINGERPRINT_OK) {
      notifyClients(String("Delete of finger template #") + id + " from sensor failed with code " + result);
      return;

    } else {
      fingerList[id] = "@empty";
      Preferences preferences;
      preferences.begin("fingerList", false); 
      preferences.remove (String(id).c_str());
      preferences.end();
      Serial.println(String("Finger template #") + id + " deleted from sensor and prefs.");

    }
  }

}


void FingerprintManager::renameFinger(int id, String newName) {
  if ((id > 0) && (id <= 200)) {
    Preferences preferences;
    preferences.begin("fingerList", false); 
    preferences.putString(String(id).c_str(), newName);
    preferences.end();
    Serial.println(String("Finger template #") + id + " renamed from " + fingerList[id] + " to " + newName);
    fingerList[id] = newName;
  }
}

String FingerprintManager::getFingerListAsHtmlOptionList() {
  String htmlOptions = "";
  int counter = 0;
  for (int i=1; i<=200; i++) {
    if (fingerList[i].compareTo("@empty") != 0) {
      String option;
      if (counter == 0)
        option = "<option value=\"" + String(i) + "\" selected>" + String(i) + " - " + fingerList[i] + "</option>";
      else 
        option = "<option value=\"" + String(i) + "\">" + String(i) + " - " + fingerList[i] + "</option>";
      htmlOptions += option;
      counter++;
    }
  }
  return htmlOptions;
}

void FingerprintManager::setIgnoreTouchRing(bool state) {
  if (ignoreTouchRing != state) {
    ignoreTouchRing = state;
    if (state == true)
      notifyClients("IgnoreTouchRing is now 'on'");
    else
      notifyClients("IgnoreTouchRing is now 'off'");
  }
}

bool FingerprintManager::getIgnoreTouchRing() {
  return ignoreTouchRing;
}


bool FingerprintManager::isRingTouched() {
  if (digitalRead(touchRingPin) == LOW) // LOW = touched. Caution: touchSignal on this pin occour only once (at beginning of touching the ring, not every iteration if you keep your finger on the ring)
      return true;
  else 
      return false;
}

bool FingerprintManager::isFingerOnSensor() {
  // get an image
  uint8_t returnCode = finger.getImage();
  if (returnCode == FINGERPRINT_OK) {
    // try to find fingerprint features in image, because image taken does not already means finger on sensor, could also be a raindrop
    returnCode = finger.image2Tz();
    if (returnCode == FINGERPRINT_OK)
      return true;
  }
  return false;
}
  
void FingerprintManager::setLedRingError() {
  finger.LEDcontrol(FINGERPRINT_LED_ON, 0, FINGERPRINT_LED_RED);
}

void FingerprintManager::setLedRingWifiConfig() {
  finger.LEDcontrol(FINGERPRINT_LED_BREATHING, 250, FINGERPRINT_LED_RED);
}

void FingerprintManager::setLedRingReady() {
  if (!ignoreTouchRing)
    finger.LEDcontrol(cfgReadyMode, 250, cfgReadyColor);
  else
    finger.LEDcontrol(FINGERPRINT_LED_ON, 0, cfgReadyColor);
}

void FingerprintManager::setLedRingScan() {
  finger.LEDcontrol(FINGERPRINT_LED_FLASHING, 25, cfgScanColor, 0);
}

void FingerprintManager::setLedRingMatch() {
  finger.LEDcontrol(FINGERPRINT_LED_ON, 0, cfgMatchColor);
}

void FingerprintManager::setLedRingNoMatch() {
  finger.LEDcontrol(FINGERPRINT_LED_FLASHING, 25, cfgNoMatchColor, 0);
}

void FingerprintManager::configureLed(uint8_t readyColor, uint8_t readyMode, uint8_t scanColor, uint8_t matchColor, uint8_t noMatchColor) {
  // Map settings values to R503 color codes: 0=off, 1=red, 2=blue, 3=purple, 4=green, 5=yellow, 6=cyan, 7=white
  // R503 uses: 1=red, 2=blue, 3=purple, 4+=newer sensors only
  const uint8_t modeMap[] = { FINGERPRINT_LED_OFF, FINGERPRINT_LED_ON, FINGERPRINT_LED_BREATHING, FINGERPRINT_LED_FLASHING };
  
  cfgReadyColor = readyColor; // pass directly (0=off handled by mode, 1-7 = R503 color codes)
  cfgReadyMode = (readyMode < 4) ? modeMap[readyMode] : FINGERPRINT_LED_BREATHING;
  cfgScanColor = scanColor;
  cfgMatchColor = matchColor;
  cfgNoMatchColor = noMatchColor;
}

bool FingerprintManager::deleteAll() {
  if (finger.emptyDatabase() == FINGERPRINT_OK)
  {
    bool rc;
    Preferences preferences;
    rc = preferences.begin("fingerList", false); 
    if (rc)
        rc = preferences.clear();
    preferences.end();

    for (int i=1; i<=200; i++) {
        fingerList[i] = String("@empty");
    };
    
    return rc;
  }
  else
    return false;

}



uint8_t FingerprintManager::writeNotepad(uint8_t pageNumber, const char *text, uint8_t length) {
  uint8_t data[34];
  
  if (length>32)
    length = 32;

  data[0] = FINGERPRINT_WRITENOTEPAD;
  data[1] = pageNumber;
  for (int i=0; i<length; i++)
    data[i+2] = text[i];

  Adafruit_Fingerprint_Packet packet(FINGERPRINT_COMMANDPACKET, sizeof(data), data);                                    
  finger.writeStructuredPacket(packet);
  if (finger.getStructuredPacket(&packet) != FINGERPRINT_OK)
    return FINGERPRINT_PACKETRECIEVEERR;
  if (packet.type != FINGERPRINT_ACKPACKET)
    return FINGERPRINT_PACKETRECIEVEERR;
  return packet.data[0];
}


uint8_t FingerprintManager::readNotepad(uint8_t pageNumber, char *text, uint8_t length) {
  uint8_t data[2];

  data[0] = FINGERPRINT_READNOTEPAD;
  data[1] = pageNumber;

  Adafruit_Fingerprint_Packet packet(FINGERPRINT_COMMANDPACKET, sizeof(data), data);                                    
  finger.writeStructuredPacket(packet);
  if (finger.getStructuredPacket(&packet) != FINGERPRINT_OK)
    return FINGERPRINT_PACKETRECIEVEERR;
  if (packet.type != FINGERPRINT_ACKPACKET)
    return FINGERPRINT_PACKETRECIEVEERR;
  
  if (packet.data[0] == FINGERPRINT_OK) {
    // read data payload
    for (uint8_t i=0; i<length; i++) {
      text[i] = packet.data[i+1];
    }
  }

  return packet.data[0];

}


String FingerprintManager::getPairingCode() {
  char buffer[33];
  buffer[32] = 0; // null termination needed for convertion to string at the end
  if (readNotepad(0, (char*)buffer, 32) == FINGERPRINT_OK)
    return String((char*)buffer);
  else
    return "";
}


bool FingerprintManager::setPairingCode(String pairingCode) {
  if (writeNotepad(0, pairingCode.c_str(), 32) == FINGERPRINT_OK)
    return true;
  else
    return false;
}


// Backup & Restore

int FingerprintManager::getTemplateCount() {
  finger.getTemplateCount();
  return finger.templateCount;
}

String FingerprintManager::getFingerName(int id) {
  if (id >= 1 && id <= 200)
    return fingerList[id];
  return "@empty";
}

String FingerprintManager::exportFingerprintsToJson() {
  // Export all stored fingerprint templates as JSON array
  // Format: [{"id":1,"name":"Alex","template":"base64..."},...]
  String json = "[";
  bool first = true;
  
  for (int id = 1; id <= 200; id++) {
    if (fingerList[id] == "@empty")
      continue;
    
    // Load template from sensor into buffer
    uint8_t result = finger.loadModel(id);
    if (result != FINGERPRINT_OK) {
      Serial.println(String("Failed to load model #") + id + ", rc=" + result);
      continue;
    }
    
    // Transfer template from sensor buffer to MCU
    result = finger.getModel();
    if (result != FINGERPRINT_OK) {
      Serial.println(String("Failed to get model #") + id + ", rc=" + result);
      continue;
    }
    
    // Read template bytes from sensor serial
    // Template size for R503: 512 bytes (2 x 256 byte characteristics)
    uint8_t templateBuffer[768];
    memset(templateBuffer, 0xFF, sizeof(templateBuffer));
    int bytesRead = 0;
    
    // Read with timeout
    unsigned long startMillis = millis();
    while (bytesRead < 768 && (millis() - startMillis) < 3000) {
      if (mySerial.available()) {
        templateBuffer[bytesRead] = mySerial.read();
        bytesRead++;
        startMillis = millis(); // reset timeout on each byte
      }
    }
    
    if (bytesRead == 0) {
      Serial.println(String("No template data received for #") + id);
      continue;
    }
    
    // Encode template to base64
    String b64 = base64::encode(templateBuffer, bytesRead);
    
    // Build JSON entry
    if (!first) json += ",";
    json += "{\"id\":" + String(id) + ",";
    json += "\"name\":\"" + fingerList[id] + "\",";
    json += "\"size\":" + String(bytesRead) + ",";
    json += "\"template\":\"" + b64 + "\"}";
    first = false;
    
    Serial.println(String("Exported finger #") + id + " (" + fingerList[id] + "), " + bytesRead + " bytes");
  }
  
  json += "]";
  return json;
}

bool FingerprintManager::importFingerprintFromTemplate(int id, const String& name, const uint8_t* templateData, int templateSize) {
  if (id < 1 || id > 200 || templateSize <= 0)
    return false;
  
  // Upload template to sensor char buffer 1 via serial
  // Send FINGERPRINT_UPLOAD command (0x09) to load into char buffer 1
  uint8_t packet[] = {0x09, 0x01}; // UploadCharBuffer, buffer 1
  Adafruit_Fingerprint_Packet p(FINGERPRINT_COMMANDPACKET, sizeof(packet), packet);
  finger.writeStructuredPacket(p);
  
  if (finger.getStructuredPacket(&p) != FINGERPRINT_OK)
    return false;
  if (p.data[0] != FINGERPRINT_OK)
    return false;
  
  // Now send template data as data packets
  // Split into packets of max 128 bytes (sensor packet_len)
  int offset = 0;
  while (offset < templateSize) {
    int chunkSize = min(128, templateSize - offset);
    bool isLast = (offset + chunkSize >= templateSize);
    uint8_t packetType = isLast ? 0x08 : 0x02; // end packet or data packet
    
    Adafruit_Fingerprint_Packet dataPacket(packetType, chunkSize, (uint8_t*)(templateData + offset));
    finger.writeStructuredPacket(dataPacket);
    offset += chunkSize;
  }
  
  delay(100);
  
  // Store the char buffer to flash at the given ID
  uint8_t result = finger.storeModel(id);
  if (result == FINGERPRINT_OK) {
    // Save name to preferences
    fingerList[id] = name;
    Preferences preferences;
    preferences.begin("fingerList", false);
    preferences.putString(String(id).c_str(), name);
    preferences.end();
    Serial.println(String("Imported finger #") + id + " (" + name + ")");
    return true;
  } else {
    Serial.println(String("Failed to store imported finger #") + id + ", rc=" + result);
    return false;
  }
}

