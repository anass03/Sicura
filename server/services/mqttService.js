// services/mqttService.js
const mqtt = require("mqtt");
const { MQTT_URL } = require("../config");
const accessService = require("./accessService");

let client = null;
let onAccessRequestCb = null;

function init(onAccessRequest) {
    onAccessRequestCb = onAccessRequest;

    console.log("[mqttService] Connessione al broker MQTT:", MQTT_URL);

    // Connessione semplice senza TLS
    client = mqtt.connect(MQTT_URL);

    client.on("connect", () => {
        console.log("[mqttService] Connesso al broker MQTT:", MQTT_URL);

        client.subscribe("accesso/richiesta", (err) => {
            if (err) {
                console.error("[mqttService] Error subscribing to accesso/richiesta:", err);
            } else {
                console.log("[mqttService] Subscritta accesso/richiesta");
            }
        });
        client.subscribe("accesso/utenti", (err) => {
            if (err) {
                console.error("[mqttService] Error subscribing to accesso/utenti:", err);
            } else {
                console.log("[mqttService] Subscritta accesso/utenti");
            }
        });
    });

    client.on("error", (err) => {
        console.error("[mqttService] MQTT connection error:", err);
    });

    client.on("message", (topic, payloadBuffer) => {
        const payloadString = payloadBuffer.toString();
        console.log("[mqttService] Messaggio MQTT:", topic, payloadString);

        try {
            const payload = JSON.parse(payloadString);

            if (topic === "accesso/richiesta") {
                if (onAccessRequestCb) onAccessRequestCb(payload);
            } else if (topic === "accesso/utenti") {
                // ci aspettiamo messaggi con campo "action"
                if (payload.action === "ENROLL_RESULT") {
                    // 👇 Arduino dice: viso registrato sì/no
                    accessService.handleFaceEnrollResult(payload);
                }else if (payload.action === "DELETE_RESULT"){
                    accessService.handleDeleteResult(payload);
                }
            }
        } catch (err) {
            console.error("[mqttService] JSON non valido:", err);
        }
    });

}

function publishDecision(payload) {
    if (!client) {
        console.warn("[mqttService] MQTT non inizializzato, decisione ignorata");
        return;
    }

    const msg = JSON.stringify(payload);
    console.log("[mqttService] Pubblico accesso/decisione:", msg);

    client.publish("accesso/decisione", msg);
}
function publishUserUpdate(update) {
    if (!client) {
        console.warn("[mqttService] client non inizializzato");
        return;
    }

    const payloadStr = JSON.stringify(update);

    console.log("[mqttService] PUB MQTT user update su accesso/utenti:", payloadStr);
    client.publish("accesso/utenti", payloadStr);  // 👈 topic fisso
}

module.exports = {
    init,
    publishDecision,
    publishUserUpdate
};
