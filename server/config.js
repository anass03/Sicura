// server/config.js
const path = require("path");

module.exports = {
    MQTT_URL: "mqtt://localhost:1883",          // o il tuo URL
    MQTT_CA_PATH: require("path").join(__dirname, "mosq-certs", "mqtt_ca.crt"),
    TELEGRAM_TOKEN: "8213309720:AAHnYD7f_AD3vd2cOd33FJbWjT9XzNaewuA",        // token BotFather
    PORT: 3000,
    JWT_SECRET: "cambia-questa-frase-segreta", // metti una stringa forte
    DATA_FILE: path.join(__dirname, "data", "users.json")
};
