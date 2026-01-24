
#include "faceID.h"


// -------------------- CHECKSUM --------------------
uint8_t parity(uint8_t *packet, int len) {
  uint8_t p = 0;
  for (int i = 2; i < len; i++)   // XOR di tutto tranne SyncWord
    p ^= packet[i];
  return p;
}

// -------------------- RUBRICA UTENTI --------------------


  UserEntry userTable[MAX_USERS];

String currentUser = "";   

void clearUserTable() {
  for (int i = 0; i < MAX_USERS; i++) {
    userTable[i].uid    = 0;
    userTable[i].name[0]= '\0';
    userTable[i].isAdmin= 0;
    userTable[i].valid  = false;
  }
}

void setUser(uint16_t uid, const char* name, uint8_t isAdmin = 0) {
  int freeIndex = -1;
  int foundIndex = -1;

  for (int i = 0; i < MAX_USERS; i++) {
    if (userTable[i].valid && userTable[i].uid == uid) {
      foundIndex = i;
      break;
    }
    if (!userTable[i].valid && freeIndex == -1) {
      freeIndex = i;
    }
  }

  int idx = foundIndex;
  if (idx == -1) {
    if (freeIndex != -1) idx = freeIndex;
    else idx = 0; // se piena, sovrascrive il primo
  }

  userTable[idx].uid = uid;
  strncpy(userTable[idx].name, name, 32);
  userTable[idx].name[32] = '\0';
  userTable[idx].isAdmin = isAdmin;
  userTable[idx].valid = true;

  Serial.print("  [RUBRICA] UID=");
  Serial.print(uid);
  Serial.print(" NAME=\"");
  Serial.print(userTable[idx].name);
  
}

const char* findNameByUid(uint16_t uid) {
  for (int i = 0; i < MAX_USERS; i++) {
    if (userTable[i].valid && userTable[i].uid == uid) {
      return userTable[i].name;
    }
  }
  return nullptr;
}

int findUserIndexByName(const String& name) {
  for (int i = 0; i < MAX_USERS; i++) {
    if (userTable[i].valid && name.equals(String(userTable[i].name))) {
      return i;
    }
  }
  return -1;
}

//--------------STAMPA RUBRICA----------------

void printUserTable() {
  Serial.println("  users:");

  bool any = false;
  for (int i = 0; i < MAX_USERS; i++) {
    if (!userTable[i].valid) continue;
    any = true;

    Serial.print("    UID=");
    Serial.print(userTable[i].uid);
    Serial.print("  NAME=\"");
    Serial.print(userTable[i].name);
  
  }

  if (!any) {
    Serial.println("    (no user saved)");
  }
}








// -------------------- CMD ZERO DATA --------------------
void sendNoDataCmd(uint8_t msgID) {
  uint8_t packet[6];

  packet[0] = 0xEF;
  packet[1] = 0xAA;
  packet[2] = msgID;
  packet[3] = 0x00;   // size high
  packet[4] = 0x00;   // size low
  packet[5] = parity(packet, 5);

  Serial1.write(packet, 6);
}

// -------------------- ENROLL  --------------------
void sendEnroll(const char* username) {
  
  uint8_t packet[2 + 1 + 2 + 35 + 1];
  int idx = 0;

  packet[idx++] = 0xEF;
  packet[idx++] = 0xAA;
  packet[idx++] = 0x1D;  // MSG: enroll
  packet[idx++] = 0x00;
  packet[idx++] = 35;    // SIZE CORRETTA

  packet[idx++] = 0x00;  // admin = 0

  for (int i = 0; i < 32; i++)
    packet[idx++] = (i < (int)strlen(username)) ? username[i] : 0x00;

  packet[idx++] = 0x00;  // face_dir = 0 (frontale)
  packet[idx++] = 20;    // timeout

  packet[idx] = parity(packet, idx);

  Serial.print(">>> ENROLL user=\"");
  Serial.print(username);
  Serial.println("\"");
  Serial1.write(packet, idx + 1);
}

void enrollFront(const char* username) {
  currentUser = username;
  sendEnroll(username);
}

// -------------------- DELETE USER --------------------
void deleteUser(uint16_t uid) {
  uint8_t packet[2 + 1 + 2 + 2 + 1];
  int idx = 0;

  packet[idx++] = 0xEF;
  packet[idx++] = 0xAA;
  packet[idx++] = 0x20;  // delete user
  packet[idx++] = 0x00;
  packet[idx++] = 0x02;  // size = 2

  packet[idx++] = uid >> 8;
  packet[idx++] = uid & 0xFF;

  packet[idx] = parity(packet, idx);

  Serial.print(">>> DELETE UID=");
  Serial.println(uid);
  Serial1.write(packet, idx + 1);


String json = "{";
      json += "\"action\":\"DELETE_RESULT\",";
      json += "\"telegramUsername\":\"" +delateName+ "\",";
      json += "\"success\":true";
      json += "}";

      mqttClient.beginMessage(topic_users);
      mqttClient.print(json);
      mqttClient.endMessage();

      Serial.println("MQTT -> DELETE USER");
      Serial.println(json);


}

// -------------------- UNLOCK --------------------
void unlockDoor() {
  uint8_t packet[2 + 1 + 2 + 2 + 1];
  int idx = 0;

  packet[idx++] = 0xEF;
  packet[idx++] = 0xAA;
  packet[idx++] = 0x12;   // unlock command

  packet[idx++] = 0x00;
  packet[idx++] = 0x02;   // size = 2

  packet[idx++] = 0x00;   // need_poweroff
  packet[idx++] = 20;     // timeout più lungo

  packet[idx] = parity(packet, idx);

  Serial.println(">>> UNLOCK start (timeout 20s)");
  Serial1.write(packet, idx + 1);
}

// -------------------- INIT CAMERA --------------------
/*void initCamera() {
  Serial.println(">>> INIT CAMERA (0x10)");
  sendNoDataCmd(0x10);
}  init che resetta
*/
bool fmReady = false;
unsigned long fmInitAt = 0;

void fmInit() {
  Serial.println(">>> INIT CAMERA (0x02 o 0x11)");
  fmReady = false;
  fmInitAt = millis();
  sendNoDataCmd(0x02);   // ping/status, NON 0x10
}


// -------------------- PARSE MESSAGES --------------------
void parseReply(uint8_t* data, int len) {
  bool status=false;
  if (len < 2) return;

  uint8_t msgID  = data[0];
  uint8_t result = data[1];

  Serial.print("[REPLY] MsgID=0x");
  Serial.print(msgID, HEX);
  Serial.print("  Result=");
  Serial.println(result);

  if (result == 0)
    Serial.println("  ✔ succesful");
  else
    Serial.println("  ✖ ERROR!");

  // INIT CAMERA
 /* if (msgID == 0x10 && result == 0) {
    Serial.println("  → Camera inizializzata");
  }*/

  if (msgID == 0x02 && result == 0) {
  fmReady = true;
  Serial.println("FM225: status OK, ready.");
}





  // ENROLL
  else if (msgID == 0x1D && result == 0) {
    unlockInProgress = false;
    // reply_data: uid(2) + face_dir(1)
    if (len >= 5) {
      uint16_t uid = (data[2] << 8) | data[3];
      uint8_t face_dir = data[4];
      Serial.print("  → Enroll registred: UID=");
      Serial.print(uid);
      Serial.print(" face_dir=0x");
      Serial.println(face_dir, HEX);

      if (currentUser.length() > 0) {
        setUser(uid, currentUser.c_str(), 0);
        Serial.print("     USER=\"");
        Serial.print(currentUser);
        Serial.println("\"");
        status=true;
       String cleanUser = currentUser;
      if (cleanUser.startsWith("@")) {
           cleanUser.remove(0, 1);
        }

        String json = "{";
            json += "\"action\":\"ENROLL_RESULT\",";
            json += "\"telegramUsername\":\"" + cleanUser + "\",";
            json += "\"success\":";
            json += status ? "true" : "false";
            json += "}";

          mqttClient.beginMessage(topic_users);
      mqttClient.print(json);
      mqttClient.endMessage();
      
      Serial.println("MQTT -> ENROLL_RESULT SUCCESS");
      Serial.println(json);
               mexShow("face enrolled", "", 1500);
              setLeds(false, true, false); 
              smartDelay(500);
             setLeds(false, false, false);
              
      }
    }
  }else if (msgID == 0x1D && result != 0) {

      status=false;


    if (currentUser.length() > 0) {
        
       String cleanUser = currentUser;
      if (cleanUser.startsWith("@")) {
           cleanUser.remove(0, 1);
        }

       String json = "{";
      json += "\"action\":\"ENROLL_RESULT\",";
      json += "\"telegramUsername\":\"" + cleanUser + "\",";
      json += "\"success\":false";
      json += "}";

      mqttClient.beginMessage(topic_users);
      mqttClient.print(json);
      mqttClient.endMessage();

      Serial.println("MQTT -> ENROLL_RESULT FAIL");
      Serial.println(json);


          mexShow("enroll.....", "Error",1500);
          
           setLeds(false, false, true);
           smartDelay(500);
             setLeds(false, false, false);

      }


  }
  // UNLOCK
  else if (msgID == 0x12) {
              mexUnlock();
              unlockInProgress = false; 

    if (result == 0) {
      Serial.println("  → unlock");

      if (len >= 4) {
        uint16_t uid = (data[2] << 8) | data[3];

        char name[33] = {0};
        uint8_t isAdmin = 0;
        uint8_t unlockStatus = 0;

        // se il firmware mette anche il nome nel payload:
        if (len >= 4 + 32) {
          for (int i = 0; i < 32; i++) {
            name[i] = data[4 + i];
          }
          name[32] = '\0';
          for (int i = 31; i >= 0; i--) {
            if (name[i] == '\0' || name[i] == 0x00 || name[i] == ' ')
              name[i] = '\0';
            else
              break;
          }
        }
        if (len >= 4 + 32 + 1) {
          isAdmin = data[4 + 32];
        }
        if (len >= 4 + 32 + 2) {
          unlockStatus = data[4 + 32 + 1];
        }

        Serial.print("     UID: ");
        Serial.println(uid);

        if (name[0] != '\0') {
          Serial.print("     USER: \"");
          Serial.print(name);
          Serial.println("\"");
          setUser(uid, name, isAdmin);
           user_name=name; ////////////////////////////////////
        } else {
          const char* localName = findNameByUid(uid);
          if (localName) {
            Serial.print("     USER (da rubrica): \"");
            Serial.print(localName);
            Serial.println("\"");

            
            user_name=localName;
           

          } else {
            Serial.println("     USER: (unknown)");
          }
        }

      
        Serial.print(" unlockStatus=");
        Serial.println(unlockStatus);
        mexShow("User", "found", 1500);
         setLeds(false, true, false);  
         currentState= ARDUINO_TO_SERVER;

      }
    } else if (result == 8) {
      Serial.println("  → UNKNOWNUSER");
       mexShow("unknownuser", "", 1500);
       smartDelay(1000);
        user_name="unknownuser";
         setLeds(false, true, false);  
      currentState= ARDUINO_TO_SERVER;


    } else if (result == 13) {
      setLeds(false, false, true);  
      Serial.println("  → Timeout");
     mexShow("Timeout", "", 1500);
      setLeds(false, false, false);
       currentState= SERVER_TO_ARDUINO;
    }
  }
  // GET ALL USERS (0x24)
  else if (msgID == 0x24 && result == 0) {
    Serial.println("  → user list");
    printUserTable();
  }



}


void parseNote(uint8_t* data, int len) {
  if (len < 1) return;
  uint8_t nid = data[0];

  if (nid == 0x00) {
    fmReady = true;
    Serial.println("[NOTE] Device ready");
  }
  else if (nid == 0x01 && len >= 17) {
    uint16_t state  = (data[1] << 8) | data[2];
    uint16_t left   = (data[3] << 8) | data[4];
    uint16_t top    = (data[5] << 8) | data[6];
    uint16_t right  = (data[7] << 8) | data[8];
    uint16_t bottom = (data[9] << 8) | data[10];
    uint16_t yaw    = (data[11] << 8) | data[12];
    uint16_t pitch  = (data[13] << 8) | data[14];
    uint16_t roll   = (data[15] << 8) | data[16];

    Serial.print("[FACE] state=");
    Serial.print(state);
    Serial.print(" box=(");
    Serial.print(left); Serial.print(",");
    Serial.print(top); Serial.print(",");
    Serial.print(right); Serial.print(",");
    Serial.print(bottom); Serial.print(")");
    Serial.print(" yaw=");   Serial.print(yaw);
    Serial.print(" pitch="); Serial.print(pitch);
    Serial.print(" roll=");  Serial.println(roll);
/*
    if (state == 0x00){ Serial.println("   → OK: volto in posizione"); if (!mexLocked) showIfChanged("face detected","");  }
    if (state == 0x01){ Serial.println("   → Nessun volto rilevato");  if (!mexLocked)  showIfChanged("no face","detected");    }
    if (state == 0x02){ Serial.println("   → Volto troppo in alto"); if (!mexLocked) showIfChanged(" face too","top");    }
    if (state == 0x03){ Serial.println("   → Volto troppo in basso");  if (!mexLocked) showIfChanged(" face too","bottom");    }
    if (state == 0x04){ Serial.println("   → Volto troppo a sinistra"); if (!mexLocked) showIfChanged(" face too","left");    }
    if (state == 0x05){ Serial.println("   → Volto troppo a destra"); if (!mexLocked) showIfChanged(" face too","right");    }
    if (state == 0x06){ Serial.println("   → Volto troppo lontano"); if (!mexLocked)  showIfChanged(" face too","far");    }
    if (state == 0x07){ Serial.println("   → Volto troppo vicino");  if (!mexLocked) showIfChanged(" face too","close");    }
    if (state == 0x08){ Serial.println("   → Sopracciglia coperte"); if (!mexLocked) showIfChanged("eyebrows hided","");    }
    if (state == 0x09){ Serial.println("   → Occhi coperti"); if (!mexLocked) showIfChanged("eyes hided","");    }
    if (state == 0x0A){ Serial.println("   → Viso coperto");  if (!mexLocked) showIfChanged("face hided","");    }
    if (state == 0x0B){ Serial.println("   → Direzione errata per l’enroll");  if (!mexLocked) showIfChanged("wrong direction","to enroll");    }
    if (state == 0x0D){ Serial.println("   → Occhi chiusi"); if (!mexLocked) showIfChanged("eyes blinked","");    }
    */
  }
  else {
    Serial.print("[NOTE] NID=");
    Serial.println(nid, HEX);
  }
}

// -------------------- RECEIVE LOOP --------------------
void readFM225() {
  static uint8_t sync[2] = {0, 0};

  while (Serial1.available()) {
    sync[0] = sync[1];
    sync[1] = Serial1.read();

    if (sync[0] != 0xEF || sync[1] != 0xAA)
      continue;

    while (Serial1.available() < 3);
    uint8_t msgType = Serial1.read();
    uint16_t size = (Serial1.read() << 8) | Serial1.read();

    if (msgType == 2) {
      Serial.print("[IMAGE] Scarto ");
      Serial.print(size);
      Serial.println(" bytes");
      for (uint16_t i = 0; i < size + 1; i++) {
        while (!Serial1.available());
        Serial1.read();
      }
      continue;
    }

    uint16_t toRead = size;
    uint8_t buf[64];
    uint16_t n = (toRead < sizeof(buf)) ? toRead : sizeof(buf);

    for (uint16_t i = 0; i < n; i++) {
      while (!Serial1.available());
      buf[i] = Serial1.read();
    }

    for (uint16_t i = n; i < toRead; i++) {
      while (!Serial1.available());
      Serial1.read();
    }

    while (!Serial1.available());
    uint8_t check = Serial1.read();
    (void)check;

    if (msgType == 0) parseReply(buf, n);
    else if (msgType == 1) parseNote(buf, n);
  }
}

