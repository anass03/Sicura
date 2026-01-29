#include "arduino_to_server.h"


char ssid[] = "Wifi-name";
char pass[] = "Insert-here-the-password";

const char broker[] = "Broker-IP";
int port = 1883;

// MQTT shared instance
WiFiClient wifiClient;
MqttClient mqttClient(wifiClient);

const char* topic_richiesta  = "accesso/richiesta";
const char* topic_decisione  = "accesso/decisione";
const char* topic_users  = "accesso/utenti";


void connettiWiFi() {
  Serial.print("Connessione a ");
  Serial.println(ssid);

  while (WiFi.begin(ssid, pass) != WL_CONNECTED) {
    Serial.println("Tentativo di connessione WiFi...");
    delay(2000);
  }

  Serial.println("Connesso al WiFi!");
  Serial.print("IP: ");
  Serial.println(WiFi.localIP());
}

void connettiMQTT() {
  Serial.print("Connessione al broker MQTT...");
  while (!mqttClient.connect(broker, port)) {
    Serial.print("Errore MQTT: ");
    Serial.println(mqttClient.connectError());
    Serial.println("Ritento tra 3 secondi...");
    delay(3000);
  }
  Serial.println("Connesso al broker MQTT.");

  mqttClient.subscribe(topic_decisione);
  mqttClient.subscribe(topic_users); 
}

void StateAduinotoServer_init() {
  Serial.println("Entrato in SEND_DATA");
  
  allOff();
  
}


State StateAduinotoServer_loop() {

setLeds(false, true, false);


  if (user_name.length() == 0) {
   
    return SERVER_TO_ARDUINO;
  }
  

  uncknownFlag = (user_name == "unknownuser");
  if(uncknownFlag){
      mexShow("waiting admin", "approval ", 2000);
      unkverFlag=true;
  }else{
    mexShow("Autenticating....", " ", 2000);
  }

  
  String cleanUser = user_name;

  


  if (cleanUser.startsWith("@")) {
    cleanUser.remove(0, 1);
  }

  String json = "{";
  json += "\"telegramUsername\":\"" + cleanUser + "\",";
  json += "\"user\":\"" + cleanUser + "\",";
  json += "\"timestamp\":\"now\"";
  json += "}";

  Serial.println("send query on MQTT...");
  Serial.println(json);


  mqttClient.beginMessage(topic_richiesta);
  mqttClient.print(json);
  mqttClient.endMessage();
  verificationFlag=true;
  
  
  // Evita duplicati
  user_name = "";
   //unlockInProgress=true;

  return SERVER_TO_ARDUINO;
}
