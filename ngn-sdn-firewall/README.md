# NGN SDN Firewall (Kathará + Ryu + OVS)

Controller Ryu OpenFlow 1.3 che protegge un broker MQTT interno. Il firewall applica regole statiche (consentire solo l'host interno, bloccare porta 2020) e dinamiche (port-scan e DoS detection) e offre un'API JSON integrabile con la dashboard Node.js.
La rete di management `10.0.0.0/24` collega `ctrl` (10.0.0.1) e `s1` (10.0.0.2) per il canale OpenFlow; il traffico dati usa `10.0.10.0/24`.

## Topologia lab
- Container: `ctrl` (Ryu + API REST 8080), `s1` (OVS), `h_mqtt` (Mosquitto), `h_client` (client autorizzato), `h_out` (attaccante/Internet).
- Indirizzi dati: `h_client=10.0.10.11`, `h_mqtt=10.0.10.20`, `h_out=10.0.10.30`, gateway `10.0.10.1` sul bridge `br0` di `s1`.
- MQTT porte: 1883 (plain) e 8883 (TLS) incluse nella policy.

## Immagine controller (offline-friendly)
Il nodo `ctrl` usa una immagine dedicata basata su Python 3.8 con dipendenze fissate per evitare l'errore eventlet/Python 3.11 e senza pip/apt a runtime:
- Python 3.8, `ryu==4.34`, `eventlet==0.30.2`, `greenlet==1.1.2`.
- Dockerfile: `ctrl/Dockerfile`.

Build locale prima di lanciare il lab:
```
docker build -t ngn-sdn-firewall-ctrl -f ctrl/Dockerfile .
```

## Immagine broker MQTT
`h_mqtt` usa una immagine minimale con Mosquitto preinstallato (`h_mqtt/Dockerfile`) per evitare l'errore `mosquitto: command not found` al boot. Builda una volta:
```
docker build -t ngn-sdn-firewall-mqtt -f h_mqtt/Dockerfile .
```
`lab.conf` punta già a questa immagine (`h_mqtt[image]=ngn-sdn-firewall-mqtt`).

## Avvio rapido
1) Installare Kathará sul host. Buildare le immagini `ctrl` e `h_mqtt` (una tantum, vedi sopra).
2) Dal repo, lanciare il lab:
```
cd ngn-sdn-firewall
kathara lstart
```
3) Connettersi alla console del controller per log ed API:
```
kathara connect ctrl
```
Il controller parte con `ryu-manager /shared/sdn_firewall.py` e API REST su `0.0.0.0:8080` nel container. Per raggiungerla dal host senza route verso `10.0.0.0/24`, usa il proxy host `http://127.0.0.1:18080` descritto sotto (dentro il lab resta disponibile anche `http://10.0.0.1:8080`).

## Policy firewall (OpenFlow 1.3)
- Statiche: table-miss verso controller; drop globale TCP dst 2020; MQTT (1883/8883) consentito solo da `10.0.10.11` verso `10.0.10.20` (gli altri pacchetti MQTT vengono droppati dal controller senza installare flow di allow).
- Dinamiche:
  - Port-scan detection: se una sorgente contatta ≥6 porte diverse verso `h_mqtt` entro 10s → evento `PORTSCAN_DETECTED` + drop per IP sorgente verso MQTT con `hard_timeout=30s`.
  - DoS detection: se una sorgente supera 120 pkt entro 5s verso `h_mqtt` → evento `DOS_DETECTED` + drop per 60s (hard_timeout).
- Logging eventi: `BLOCK_IP`, `UNBLOCK_IP`, `PORTSCAN_DETECTED`, `DOS_DETECTED`, `MQTT_DENIED` con timestamp e dettagli.
- Metriche: regole attive stimate, IP bloccati, contatori eventi, traffico verso MQTT (pkt/byte) e top talkers (via flow stats).

## Test rapidi
Tutte le console si aprono con `kathara connect <nodo>`.

- **Allow MQTT da client**
```
h_client$ nc -vz 10.0.10.20 1883
```
Dovrebbe aprire la connessione. In controller vedrai flow allow con idle_timeout.

- **Deny MQTT da h_out**
```
h_out$ nc -vz 10.0.10.20 1883
```
Il controller logga `MQTT_DENIED`. Con traffico ripetuto si attiva `DOS_DETECTED` e blocco temporaneo.

- **Port-scan detection**
```
h_out$ nmap -p 1800-1815 10.0.10.20
```
Al superamento soglia appare `PORTSCAN_DETECTED`, poi drop IP per 30s.

- **DoS simulation** (veloce flood SYN)
```
h_out$ hping3 -S -p 1883 --faster 10.0.10.20
```
Dopo ~120 pkt in 5s viene loggato `DOS_DETECTED` e installato blocco 60s.

- **Broker MQTT**
Usa `mosquitto_pub` / `mosquitto_sub` o `nc` per un semplice handshake.

## API REST (integra con dashboard Node/Express)
Base URL da host (proxy locale): `http://127.0.0.1:18080`  
Base URL interno al lab: `http://10.0.0.1:8080`

- Stato e metriche
```
curl http://127.0.0.1:18080/api/firewall/status
# include anche blocked_ports, traffico, top talkers
```

- Ultimi eventi (max 500, default 200)
```
curl "http://127.0.0.1:18080/api/firewall/events?limit=50"
```

- Blocco manuale
```
curl -X POST http://127.0.0.1:18080/api/firewall/block \
  -H 'Content-Type: application/json' \
  -d '{"ip":"10.0.10.30","seconds":90}'
```

- Sblocco manuale
```
curl -X POST http://127.0.0.1:18080/api/firewall/unblock \
  -H 'Content-Type: application/json' \
  -d '{"ip":"10.0.10.30"}'
```

- Blocco porta TCP (scope mqtt=solo verso 10.0.10.20, scope global=LAN intera)
```
curl -X POST http://127.0.0.1:18080/api/firewall/block_port \
  -H 'Content-Type: application/json' \
  -d '{"port":1883,"scope":"mqtt","seconds":120,"override_allow":false}'
```

- Sblocco porta TCP
```
curl -X POST http://127.0.0.1:18080/api/firewall/unblock_port \
  -H 'Content-Type: application/json' \
  -d '{"port":1883,"scope":"mqtt"}'
```

Eventi aggiunti: `PORT_BLOCKED`, `PORT_UNBLOCKED` (reason `MANUAL_PORT_BLOCK`, `MANUAL_PORT_UNBLOCK` o `timeout`).

## File principali
- `shared/sdn_firewall.py`: app Ryu + API REST, enforcement L3/L4, detection e flow install/remove.
- `shared/firewall_logic.py`: stato, contatori, detection port-scan/DoS, gestione blocklist.
- `shared/firewall_api.py`: endpoint REST.
- `shared/of_helpers.py`: helper OpenFlow.
- `s1/startup`, `ctrl/startup`, `h_* /startup`: configurazione nodi lab (subnet 10.0.10.0/24 per il traffico dati, MGMT 10.0.0.0/24).

## Dashboard web (porta 3000)
- URL: `http://localhost:3000` (login admin) e nuova pagina `http://localhost:3000/firewall` per il pannello SDN.
- Variabile env backend per il proxy verso Ryu: `RYU_API_BASE` (default `http://127.0.0.1:18080`, fallback `http://10.0.0.1:8080`). Il backend espone `/api/ui/firewall/*` come proxy autenticato.
- Pagina SDN Firewall: overview regole attive, MQTT hosts/sorgenti consentite, contatori eventi, traffico verso MQTT (pkts/bytes), top talkers, liste IP/porte bloccate, tabella eventi filtrabile, azioni manuali (block/unblock IP e porte con scope e override della allow rule).
- UI auto-refresh ogni ~3-4s; gli stati bloccati sono evidenziati in rosso, quelli OK in verde. Usa l'header JWT già presente nel resto della dashboard.
- Screenshot descrittivo: la pagina mostra due righe di card (overview, traffico, blocked IP/ports) e sotto tabella eventi + form di controllo manuale.

## Accesso API + dashboard dal host (senza route verso 10.0.0.0/24)
1) Avvia il lab:
```
cd ngn-sdn-firewall
kathara lstart
```
2) Dal root del repo, avvia il piccolo proxy host (richiede docker e python3):
```
cd ..
./tools/ryu_host_proxy.py
```
3) Testa dal host:
```
curl http://127.0.0.1:18080/api/firewall/status
```
4) Avvia la dashboard backend:
```
cd server
node server.js
```
5) Apri la UI: `http://localhost:3000/firewall`

Per fermare il proxy: Ctrl+C sul processo `ryu_host_proxy.py`.

## Troubleshooting
- Verificare che il proxy sia attivo sul host: `ss -lntp | grep 18080` deve mostrare `127.0.0.1:18080` in ascolto (processo python).
- Nome container `ctrl`: `docker ps | grep ctrl` (serve al proxy per ricavare l'IP reale del container).
- Se `curl http://127.0.0.1:18080/api/firewall/status` fallisce, controlla l'IP del container e la porta nel container: `docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' $(docker ps --format '{{.Names}}' | grep '_ctrl_' | head -n1)` e poi `kathara connect ctrl` con `ss -lntp | grep 8080`.
- Verificare che Ryu giri: in `kathara connect ctrl` dovresti vedere `ryu-manager ...` in foreground. In alternativa `ps -ef | grep ryu-manager`.
- Verificare che `s1` sia connesso: `ovs-vsctl get-controller br0` e `ovs-vsctl show` su `s1` devono riportare `tcp:10.0.0.1:6633`.
- Verificare OpenFlow13: `ovs-vsctl get bridge br0 protocols` deve restituire `["OpenFlow13"]`.
- Connettività base: ping tra `h_client`, `h_mqtt`, `h_out` verso `10.0.10.1` e tra loro per confermare il bridge.
- Test MQTT consentito/bloccato: `nc -vz 10.0.10.20 1883` da `h_client` (ok) e da `h_out` (deny, vedi log su ctrl); `nmap -p 1800-1815 10.0.10.20` su `h_out` per trigger port-scan detection.
- Se serve un reset pulito: `kathara lclean` e poi `kathara lstart`.
