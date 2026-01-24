#ifndef SERVER_TO_ARDUINO_H
#define SERVER_TO_ARDUINO_H

#include <WiFiS3.h>
#include <ArduinoMqttClient.h>
#include "state.h"
#include "arduino_to_server.h"
#include "hardware.h"
#include "faceID.h"
#include "keypad_step.h"

extern char password[7];

extern const char broker[];
extern int port;
extern State currentState;
extern WiFiClient wifiClient;
extern MqttClient mqttClient;

extern const char* topic_decisione;
extern bool unlockInProgress;
extern bool mexLocked;
extern unsigned long mexUntil;
extern bool uncknownFlag;
extern bool verificationFlag;
extern bool unkverFlag;
void showIfChanged(const String& l1, const String& l2);
void mexShow(const String& l1, const String& l2, unsigned long ms = 0);
void mexUnlock();
void messageReceived(int messageSize);
void StateServertoArduino_init();
State StateServertoArduino_loop();

#endif
