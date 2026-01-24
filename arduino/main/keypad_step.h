#ifndef KEYPAD_STEP_H
#define KEYPAD_STEP_H

#include <Adafruit_Keypad.h>
#include <LiquidCrystal_I2C.h>
#include "state.h"
#include "hardware.h"
#include "server_to_arduino.h"


const byte ROWS = 4;
const byte COLS = 4;



extern Adafruit_Keypad keypad;
extern Adafruit_Keypad keypadConf;


void  StateKeypadStep_init();
State  StateKeypadStep_loop(char password[]);

#endif