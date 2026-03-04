// server.js
const express = require("express");
const cors = require("cors");
const path = require("path");
const { PORT } = require("./config");

const accessService = require("./services/accessService");
const mqttService = require("./services/mqttService");
const telegramService = require("./services/telegramService");

const fs = require("fs");         // <--- aggiunto
// inizializza servizi dominio
mqttService.init(accessService.handleAccessRequest);
accessService.init(mqttService, telegramService);

const app = express();
app.use(cors({
    origin: "https://dashboard.sicura.click",
    credentials: true
}));

app.use(express.json());

// API
app.use("/api/auth", require("./routes/authRoutes"));
app.use("/api", require("./routes/accessRoutes"));
app.use("/api/ui/firewall", require("./routes/firewallRoutes"));
app.use("/api/ui/lab", require("./routes/labRoutes"));

// frontend statico
app.use(express.static(path.join(__dirname, "public")));

// pagina dedicata firewall
app.get("/firewall", (req, res) => {
    res.sendFile(path.join(__dirname, "../ngn-sdn-firewall", "firewall.html"));
});

app.get("*", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "index.html"));
});


app.listen(3000, () => {
    console.log("Backend HTTP in ascolto su http://localhost:3000");
});
