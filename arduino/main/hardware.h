#ifndef HARDWARE_H
#define HARDWARE_H

#include <LiquidCrystal_I2C.h>
#include <Wire.h>
#include "keypad_step.h"
#include "arduino_to_server.h"


extern LiquidCrystal_I2C lcd;


void initLedsAndBuzzer();



void initBeepTimer();   // timer interrupt

void handleBuzzer();    // tone/noTone

void beepClick();       // beep keypad

void smartDelay(unsigned long ms);


void setLeds(bool verde, bool giallo, bool rosso);


void allOff();


void showLcd(const String& line1, const String& line2);

// Suono di accesso negato (bip bip bip)
void beepDenied();

// Suono breve di conferma OK
void beepOk();

#endif
