#include "keypad_step.h"

#define PASSWORD_LENGTH 6 



char keys[ROWS][COLS] = {
  {'1','2','3','A'},
  {'4','5','6','B'},
  {'7','8','9','C'},
  {'*','0','#','D'}
};

// Pin collegati

byte rowPins[ROWS] = {9, 8, 7,6};
byte colPins[COLS] = {5, 4, 3, 2};
Adafruit_Keypad keypad = Adafruit_Keypad( makeKeymap(keys), rowPins, colPins, ROWS, COLS );

extern char inputBuffer[PASSWORD_LENGTH];
extern byte inputIndex;
String passwordMask;
void  StateKeypadStep_init() {
  keypad.begin();
  Serial.println("keypad ready!");

  
 
  allOff();           // azzerare buzzer
 showLcd("enter the code", "and press #");
  inputIndex = 0;
  
passwordMask = "";
}



char inputBuffer[PASSWORD_LENGTH]; 
byte inputIndex = 0;
 


State  StateKeypadStep_loop(char password[]) {
  verificationFlag=false;
  
          unkverFlag=false;
  keypad.tick(); 
 
  
  
 
 
  while (keypad.available()) {

    keypadEvent e = keypad.read();

    if (e.bit.EVENT == KEY_JUST_RELEASED) {
       beepClick();
        handleBuzzer();
      char key = (char)e.bit.KEY;
      Serial.println(key);

     if (key != '#') {
          passwordMask += '*';
         showLcd("Password", passwordMask);
        }
  
      if (key == '#') {
        // Conferma PIN
        bool match = true;

        if (inputIndex != PASSWORD_LENGTH) {
          match = false;
        } else {
          for (byte i = 0; i < inputIndex && i < PASSWORD_LENGTH; i++) {
            if (inputBuffer[i] != password[i]) {
              match = false;
              break;
            }
          }
        }

        if (match) {
          
          Serial.println("Unlock!");
          showLcd("Unlock!", "");
          beepOk();
          setLeds(true, false, false);
         
          smartDelay(3000); // porta aperta per 3s
          setLeds(false, false, false);
          inputIndex = 0;

        showIfChanged("Press * to", "unlock");
            return SERVER_TO_ARDUINO;

        } else {
          


          Serial.println("Denial access!");
          showLcd("wrong password", "retry");

          
          setLeds(false, false, true);
          beepDenied();

          passwordMask = "";

          inputIndex = 0; // reset buffer

          
          smartDelay(1000);
          setLeds(false, false, false);
          showLcd("enter the code", "and press #");
          
        }

      } else {
        // Aggiunta cifra al buffer
        if (inputIndex < PASSWORD_LENGTH) {
          inputBuffer[inputIndex++] = key;
          Serial.print("entered: ");
          Serial.println(key);

          if (inputIndex == PASSWORD_LENGTH) {
            showLcd("password entered", "press #");
          }
        } else {
          // Buffer pieno, chiedi di confermare
          showLcd("max size", "press #");
        }
      }
    }
  }

  
  return KEYPAD_STEP;
}

