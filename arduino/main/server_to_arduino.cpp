#include "server_to_arduino.h"

char keysConf[ROWS][COLS] = {
  {'1','2','3','A'},
  {'4','5','6','B'},
  {'7','8','9','C'},
  {'*','0','#','D'}
};


byte rowPinsConf[ROWS] = {9, 8, 7,6};
byte colPinsConf[COLS] = {5, 4, 3, 2};
Adafruit_Keypad keypadConf = Adafruit_Keypad( makeKeymap(keysConf), rowPinsConf, colPinsConf, ROWS, COLS );

bool enrollPending = false;
bool unlockInProgress = false;
bool mexLocked = false;
bool uncknownFlag=false;
unsigned long mexUntil = 0;

bool verificationFlag=false;
bool unkverFlag=false;
 String pendingUserName;
String delateName;

void StateServertoArduino_init() {
 
  
    
   Serial1.begin(115200);
 
  setLeds(false, false, false);
   

  Serial.println("server_to_arduino");
  keypadConf.begin();
 
}


State StateServertoArduino_loop() {
 if (mexLocked && mexUntil > 0 && millis() > mexUntil) mexUnlock();

 
  if (!mexLocked) {
    if (enrollPending) showIfChanged("Press # to", "enroll face");
    else if (!verificationFlag && !unlockInProgress) showIfChanged("Press * to", "unlock");
    else if(unkverFlag && verificationFlag && !unlockInProgress)showIfChanged("waiting admin", "approval ");
    else if(verificationFlag && !unlockInProgress)showIfChanged("verification", "in progress");
    
    
    
  }
  readFM225();

  if (!mqttClient.connected()) {
    connettiMQTT();
  }
  mqttClient.poll();
  keypadConf.tick();
  while (keypadConf.available()) {
    keypadEvent e = keypadConf.read();
    char k = (char)e.bit.KEY;

      

    if (e.bit.EVENT == KEY_JUST_RELEASED) {
        beepClick();
        handleBuzzer();
      if (enrollPending && k == '#') {
        if (!unlockInProgress) {
              
        unlockInProgress=true;
        showIfChanged("enroll...", "don't move"); // 0
        
             
        enrollFront(pendingUserName.c_str());
        currentState=SERVER_TO_ARDUINO;
        enrollPending = false;
        }
      }else if (k == '*') {

        Serial.print("unlockInProgress=");
        Serial.println(unlockInProgress);
        
          if (!unlockInProgress) {
              unlockInProgress = true;
              showIfChanged("face", "verification"); // 0
              unlockDoor();
             
          }
      
      }
    }
  }

 return currentState;
}

String lastL1 = "", lastL2 = "";

void mexShow(const String& l1, const String& l2, unsigned long ms ) {
  showLcd(l1, l2);
  lastL1 = l1;
  lastL2 = l2;
  mexLocked = true;
  mexUntil = (ms > 0) ? millis() + ms : 0;
}

void mexUnlock() {
  mexLocked = false;
  mexUntil = 0;
}




void showIfChanged(const String& l1, const String& l2) {  //evito scritte fiacche
  if (l1 != lastL1 || l2 != lastL2) {
    showLcd(l1, l2);
    lastL1 = l1;
    lastL2 = l2;
  }
}






void messageReceived(int messageSize) {
 
  String payload = mqttClient.readString();
  Serial.println("recived via callback: " + payload);

  // Controllo "OK" ovunque nel messaggio
  if (payload.indexOf("OK") != -1) {

    if(uncknownFlag){

         Serial.println("Unlock!");
         setLeds(true, false, false);
          mexShow("Unlock!", "",2000);
          beepOk();
           unkverFlag=false;
          uncknownFlag=false;
          unlockInProgress=false;
          verificationFlag=false;
          setLeds(false, false, false);
            currentState=SERVER_TO_ARDUINO;  

    }else {
    
      String otp = payload.substring(23, 29);  
      Serial.println("password recived: " + otp);
      otp.toCharArray(password, 7);  // Copia OTP in password

      
      setLeds(false, true, false);
      beepOk();
      mexShow("OK", "enter the password", 0);
      unlockInProgress=false;
      currentState = KEYPAD_STEP;  

     
    }
  }  else if (payload.indexOf("START_ENROLL") != -1) {
    int start = payload.indexOf("\"telegramUsername\":\"");
    if (start != -1) {
      start += strlen("\"telegramUsername\":\"");
      int end = payload.indexOf('"', start);
      pendingUserName = (end == -1) ? payload.substring(start)
                                    : payload.substring(start, end);
      pendingUserName.trim();

      
      enrollPending = true;
    }

  }else if(payload.indexOf("DELETE") != -1) {
        
       int start = payload.indexOf("\"telegramUsername\":\"");
 
    if (start != -1) {
        start += strlen("\"telegramUsername\":\"");  

        int end = payload.indexOf('"', start);       // virgolette finali

  
      String pendingUserName;

      if (end == -1) {
        pendingUserName = payload.substring(start);
      }else { 
          pendingUserName = payload.substring(start, end);
      }

      pendingUserName.trim(); //remove several /0 or tab

    String arg = pendingUserName;
    arg.trim();
int idx = findUserIndexByName(arg);
   
   
    if (idx >= 0) {
      uint16_t uid = userTable[idx].uid;
      Serial.print("Delete user \"");
      Serial.print(userTable[idx].name);
      mexShow("Delete user", arg, 2000);
      setLeds(false, true, false);
      delateName=String(userTable[idx].name); //String no
      delateName.trim();
      Serial.print("\" (UID=");
      Serial.print(uid);
      Serial.println(")");
      deleteUser(uid);
      userTable[idx].valid = false;

    } else {
  // fallback: provo come numero UID
  uint16_t uid = arg.toInt();
  if (uid > 0) {
    Serial.print("no user with this name \"");
    Serial.print(arg);
    Serial.println("\", try with numeric UID.");
 delateName=arg;
 delateName.trim();
    
    deleteUser(uid);
    setLeds(false, true, false);
  } else {
    Serial.print("user \"");
    Serial.print(arg);
    Serial.println("\"user not found.");



   
    
  }
}

    
  
    
}
   setLeds(false, false, false);
currentState = SERVER_TO_ARDUINO;
  
    }else if(payload.indexOf("KO") != -1){

        setLeds(false, false, true);
        mexShow("Access Denied", "", 2000);
        beepDenied();
       
        unlockInProgress=false;
        uncknownFlag=false;
        verificationFlag=false;
         unkverFlag=false;
         setLeds(false, false, false);
     currentState = SERVER_TO_ARDUINO; 
    } 
        
  // Svuota eventuali residui
  while (mqttClient.available()) mqttClient.read();
}
