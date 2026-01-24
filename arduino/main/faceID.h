#ifndef FACEID_H
#define FACEID_H

#include <Arduino.h>
#include "state.h"
#include "hardware.h"
#include "arduino_to_server.h"
#include "server_to_arduino.h"
const int MAX_USERS = 32;

struct UserEntry {
  uint16_t uid;
  char     name[33];
  uint8_t  isAdmin;
  bool     valid;
};

extern UserEntry userTable[MAX_USERS];
extern String delateName;
uint8_t parity(uint8_t *packet, int len);
void clearUserTable() ;
void setUser(uint16_t uid, const char* name, uint8_t isAdmin) ;
const char* findNameByUid(uint16_t uid);
int findUserIndexByName(const String& name);
void printUserTable();
void sendNoDataCmd(uint8_t msgID);
void enrollFront(const char* username);
void sendEnroll(const char* username);
void deleteUser(uint16_t uid) ;
void unlockDoor();
//void initCamera();
void parseReply(uint8_t* data, int len);
void parseNote(uint8_t* data, int len);
void readFM225();
void fmInit();



#endif
