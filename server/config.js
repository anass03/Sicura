// server/config.js
const path = require("path");

module.exports = {
    MQTT_URL: "mqtt://localhost:1883",          // o il tuo URL
    MQTT_CA_PATH: require("path").join(__dirname, "mosq-certs", "mqtt_ca.crt"),
    TELEGRAM_TOKEN: process.env.TELEGRAM_TOKEN,        // token BotFather
    PORT: 3000,
    JWT_SECRET: process.env.JWT_SECRET, // metti una stringa forte
    DATA_FILE: path.join(__dirname, "data", "users.json"),
    RYU_API_BASE: process.env.RYU_API_BASE || "http://127.0.0.1:18080",
};
