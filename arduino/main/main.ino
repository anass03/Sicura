#include "keypad_step.h"
#include "arduino_to_server.h"
#include "server_to_arduino.h"
#include "faceID.h"
#include "state.h"
#include "hardware.h"



String user_name="";


char password[7]="";

State currentState =SERVER_TO_ARDUINO;
State previousState =SERVER_TO_ARDUINO;


void setup() {
  Serial.begin(9600);
  lcd.init();
  lcd.backlight();
  

  connettiWiFi();
  connettiMQTT();

  mqttClient.onMessage(messageReceived);
   
  clearUserTable();

 
  fmInit();
  lcd.begin(16, 2);        
  initLedsAndBuzzer();    
  initBeepTimer();  //interrupt timer
  allOff();                

  
  
    StateServertoArduino_init();
}


void loop() {

    handleBuzzer(); // tone/notome da timer

    if (!mqttClient.connected()) {
    connettiMQTT();   
  }
   mqttClient.poll();
 
    
    if (currentState != previousState) {
        previousState = currentState;

        switch (currentState) {
        
              case ARDUINO_TO_SERVER: 
                  StateAduinotoServer_init(); 
             break;
            case SERVER_TO_ARDUINO: 
                 StateServertoArduino_init();
             break;
            case KEYPAD_STEP: 
                 StateKeypadStep_init(); 
             break;
        }
    }

    // ESECUZIONE DELLO STATO
    switch (currentState) {
       
        case ARDUINO_TO_SERVER:  
        currentState = StateAduinotoServer_loop(); 
        break;
        case SERVER_TO_ARDUINO: 
        currentState =  StateServertoArduino_loop(); 
        break;
        case KEYPAD_STEP:  
        currentState = StateKeypadStep_loop(password); 
        break;
    }

      
}


