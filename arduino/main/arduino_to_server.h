#ifndef ARDUINO_TO_SERVER_H
#define ARDUINO_TO_SERVER_H

#include <WiFiS3.h>
#include <ArduinoMqttClient.h>
#include "server_to_arduino.h"
#include "state.h"
#include "hardware.h"
#include "faceID.h"
// WIFI
extern char ssid[];
extern char pass[];

// MQTT
extern const char broker[];
extern int port;

// MQTT CLIENT (condiviso)
extern WiFiClient wifiClient;
extern MqttClient mqttClient;

// TOPIC BASE (NON per utente)
extern const char* topic_richiesta;
extern const char* topic_decisione;
extern const char* topic_users;

extern String user_name;


void connettiWiFi();
void connettiMQTT();
void StateAduinotoServer_init();
State StateAduinotoServer_loop();

#endif
