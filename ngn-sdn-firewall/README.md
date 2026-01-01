# NGN SDN Firewall (Kathará + Ryu + OVS)

Controller Ryu OpenFlow 1.3 che protegge un broker MQTT interno. Il firewall applica regole statiche deterministiche (set_field + output, niente `NORMAL`), blocchi temporanei e detection (port-scan, DoS, SYN flood, pattern sospetti) ed espone un'API JSON per la dashboard Node.js.
La rete di management `10.0.0.0/24` collega `ctrl` (10.0.0.1) e `s1` (10.0.0.2) per il canale OpenFlow; il traffico dati è separato tra LAN interna e Internet.

## Topologia lab (edge inside/outside)
- Container: `ctrl` (Ryu + API REST 8080), `s1` (OVS firewall), `h_mqtt` (Mosquitto, DMZ interna), `h_client` (client autorizzato), `h_out` (attaccante/Internet).
- Reti dati:
  - INSIDE client: `10.0.10.0/24` (`h_client=10.0.10.11`, gateway `10.0.10.1`).
  - INSIDE mqtt/DMZ: `10.0.11.0/24` (`h_mqtt=10.0.11.20`, gateway `10.0.11.1`).
  - OUTSIDE/Internet: `10.0.20.0/24` (`h_out=10.0.20.30`, gateway `10.0.20.1`).
- MAC deterministiche (impostate negli startup) per evitare learning L2; il firewall risponde in proxy ARP per i tre gateway.
- MQTT porte: 1883 (plain) e 8883 (TLS) incluse nella policy allowlist solo da `h_client`.

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

## Immagine host tools (client/attacker)
`h_client` e `h_out` usano `ngn-host-tools` con `mosquitto-clients`, `nmap`, `hping3`, `tcpdump` e `jq` preinstallati:
```
docker build -t ngn-host-tools -f h_tools/Dockerfile .
```

## Avvio rapido
1) Installare Kathará sul host. Buildare le immagini `ctrl`, `h_mqtt` e `ngn-host-tools` (una tantum, vedi sopra).
2) Dal root del repo, avvia la dashboard (`node server/server.js`) e apri `http://localhost:3000/firewall`.
3) Avvia il proxy host (necessario per usare il bottone Start): `./tools/ryu_host_proxy.py` da root repo (richiede Docker). Il bottone resta disabilitato finché il proxy su 127.0.0.1:18080 non è up.
4) Nella dashboard, premi **Start Lab** (o **Restart Lab** in caso di stato sporco) per lanciare il laboratorio. Lo start è idempotente: se il lab è già attivo restituisce RUNNING; se i container esistono già viene fatto cleanup automatico prima di riavviare. Richiede localhost e un admin autenticato.
4) In alternativa CLI: `cd ngn-sdn-firewall && kathara lstart` e poi `kathara connect ctrl` per i log.
Il controller parte con `ryu-manager /shared/sdn_firewall.py` e API REST su `0.0.0.0:8080` nel container. Per raggiungerla dal host senza route verso `10.0.0.0/24`, usa il proxy host `http://127.0.0.1:18080` descritto sotto (dentro il lab resta disponibile anche `http://10.0.0.1:8080`).

## Policy firewall (OpenFlow 1.3, senza NORMAL)
- Pipeline base: table-miss drop, ARP puntato al controller (proxy ARP per i gateway), tap TCP→MQTT al controller. Flow deterministici con `set_field(eth_src/dst)`, `dec_ttl`, `output:<porta>` per l'allowlist MQTT (tra reti diverse). Nessun `NORMAL` e nessun flow L2 imparato.
- Dinamiche:
  - Port-scan detection: sorgente con ≥6 porte uniche verso MQTT in 10s → evento `PORTSCAN_DETECTED` + blocco IP 30s.
  - DoS detection: ≥160 pkt in 5s verso MQTT → evento `DOS_DETECTED` + blocco 60s.
  - SYN flood: tanti SYN con pochi ACK (rapporto <25%) in 3s → evento `SYN_FLOOD_DETECTED` + blocco 90s.
  - Pattern sospetti:
    * `MQTT_CONNECT_STORM`: tante nuove connessioni TCP verso 1883/8883 in 6s → blocco 75s.
    * Flag anomale (NULL/XMAS/FIN scan) → evento `SUSPICIOUS_PATTERN` + blocco 45s.
- Logging eventi: `BLOCK_IP`, `UNBLOCK_IP`, `PORT_BLOCKED`, `PORT_UNBLOCKED`, `MQTT_DENIED`, `PORTSCAN_DETECTED`, `DOS_DETECTED`, `SYN_FLOOD_DETECTED`, `SUSPICIOUS_PATTERN` con timestamp e dettagli.
- Metriche: regole attive/policy, IP/porte bloccate, contatori eventi, traffico verso MQTT (pkt/byte) e top talkers, tentativi MQTT allowed/denied per sorgente.

**Nota di design**: le policy MQTT non usano più `actions=NORMAL` o flow L2 imparati; ogni direzione ha flow simmetrici con `set_field(eth_src/eth_dst)` verso i MAC noti degli host e `dec_ttl` per il routing L3 tra le reti inside/outside. I packet-in sono solo mirror per telemetria/detection.

## Test rapidi
Tutte le console si aprono con `kathara connect <nodo>`.

- **Allow MQTT da client**
```
h_client$ nc -vz 10.0.11.20 1883
```
Dovrebbe aprire la connessione. In controller vedrai flow allow con idle_timeout.

- **Deny MQTT da h_out**
```
h_out$ nc -vz 10.0.11.20 1883
```
Il controller logga `MQTT_DENIED`. Con traffico ripetuto si attiva `DOS_DETECTED` e blocco temporaneo.

- **Port-scan detection**
```
h_out$ nmap -p 1800-1815 10.0.11.20
```
Al superamento soglia appare `PORTSCAN_DETECTED`, poi drop IP per 30s.

- **DoS simulation** (veloce flood SYN)
```
h_out$ hping3 -S -p 1883 --faster 10.0.11.20
```
Dopo ~160 pkt in 5s viene loggato `DOS_DETECTED` e installato blocco 60s.

- **SYN flood**
```
h_out$ hping3 -S -p 8883 --flood 10.0.11.20
```
Genera `SYN_FLOOD_DETECTED` e blocco 90s se gli ACK sono pochi.

- **Pattern sospetti**
```
h_out$ for i in $(seq 1 12); do nc -z -w1 10.0.11.20 1883; done   # MQTT_CONNECT_STORM
h_out$ nmap -sX -p 1883 10.0.11.20                             # XMAS/NULL/FIN scan
```
Genera `SUSPICIOUS_PATTERN` e blocco temporaneo.

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

- Blocco porta TCP (scope mqtt=solo verso 10.0.11.20, scope global=LAN intera)
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

## Demo automatica
Esegui tutti i test (baseline MQTT, deny outside, port-scan, DoS, SYN flood e pattern sospetti) e colleziona log/artifacts con:
```
cd ngn-sdn-firewall
./tests/run_demo.sh
```
Gli output finiscono in `tests/artifacts/` (status JSON, eventi, dump-flows, log nmap/hping). Il comando termina con exit code ≠0 se uno step fallisce.

## Troubleshooting
- Verificare che il proxy sia attivo sul host: `ss -lntp | grep 18080` deve mostrare `127.0.0.1:18080` in ascolto (processo python).
- Nome container `ctrl`: `docker ps | grep ctrl` (serve al proxy per ricavare l'IP reale del container).
- Se `curl http://127.0.0.1:18080/api/firewall/status` fallisce, controlla l'IP del container e la porta nel container: `docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' $(docker ps --format '{{.Names}}' | grep '_ctrl_' | head -n1)` e poi `kathara connect ctrl` con `ss -lntp | grep 8080`.
- Verificare che Ryu giri: in `kathara connect ctrl` dovresti vedere `ryu-manager ...` in foreground. In alternativa `ps -ef | grep ryu-manager`.
- Verificare che `s1` sia connesso: `ovs-vsctl get-controller br0` e `ovs-vsctl show` su `s1` devono riportare `tcp:10.0.0.1:6633`.
- Verificare OpenFlow13: `ovs-vsctl get bridge br0 protocols` deve restituire `["OpenFlow13"]`.
- Connettività base: ping verso i gateway (`10.0.10.1`, `10.0.11.1`, `10.0.20.1`) e tra host per confermare il path L3.
- Test MQTT consentito/bloccato: `nc -vz 10.0.11.20 1883` da `h_client` (ok) e da `h_out` (deny, vedi log su ctrl); `nmap -p 1800-1815 10.0.11.20` su `h_out` per trigger port-scan detection.
- Se serve un reset pulito: `kathara lclean` e poi `kathara lstart`.
- Pulsante Start disabilitato? Avvia prima il proxy `./tools/ryu_host_proxy.py` su localhost; lo stato proxy appare nel badge e abilita il bottone.
