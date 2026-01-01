# SDN Firewall quick checks

Prereqs: immagini buildate (`ngn-sdn-firewall-ctrl`, `ngn-sdn-firewall-mqtt`, `ngn-host-tools`).

1. Avvia il lab (già default-deny):
```
kathara lclean
kathara lstart
```
2. Dump flowtable:
```
kathara exec s1 -- ovs-ofctl -O OpenFlow13 dump-flows br0
```
3. API controller:
```
kathara exec ctrl -- curl -s http://127.0.0.1:8080/api/firewall/status
```
4. MQTT consentito (client interno):
```
kathara exec h_c1 -- mosquitto_pub -h 10.0.10.20 -t demo -m hi & \
kathara exec h_c1 -- mosquitto_sub -C 1 -h 10.0.10.20 -t demo
```
5. MQTT bloccato (attacker esterno):
```
kathara exec h_a1 -- nc -vz 10.0.10.20 1883
```
6. Portscan / DoS detection:
```
kathara exec h_a2 -- nmap -Pn -p 1800-1815 10.0.10.20
kathara exec h_a3 -- hping3 -S -p 1883 --faster --count 200 10.0.10.20
kathara exec ctrl -- curl -s http://127.0.0.1:8080/api/firewall/events | head
```
