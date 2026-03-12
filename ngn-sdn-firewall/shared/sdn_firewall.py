from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types, ipv4, arp, tcp, udp
from ryu.ofproto import ether
from ryu.app.wsgi import WSGIApplication
from ryu.lib import hub

import ipaddress
import json
import time
from collections import defaultdict, deque

from ryu.app.wsgi import ControllerBase, Response, route

#  Configurazione rete
MQTT_IP = "10.0.10.20"
MQTT_PORTS = {1883, 8883}

# IP che non possono mai essere bloccati (es. il broker stesso)
PROTECTED_IPS = {MQTT_IP}


def _tcp_flags_str(bits):
    """Decodifica i flag TCP in stringa leggibile (es. 'SYN+ACK')."""
    flags = []
    if bits & 0x002: flags.append("SYN")
    if bits & 0x010: flags.append("ACK")
    if bits & 0x008: flags.append("PSH")
    if bits & 0x001: flags.append("FIN")
    if bits & 0x004: flags.append("RST")
    if bits & 0x020: flags.append("URG")
    return "+".join(flags) or "?"

# Nomi porte → zona (i numeri OVS vengono scoperti a runtime)
INT_PORT_NAMES = {"eth1", "eth2", "eth3", "eth4"}
EXT_PORT_NAMES = {"eth5", "eth6", "eth7"}

#  Soglie rilevamento
DOS_THRESHOLD = 20          # pacchetti nella finestra
DOS_WINDOW = 5              # secondi
DOS_BLOCK_DURATION = 30     # secondi di blocco

PORTSCAN_THRESHOLD = 10     # porte distinte
PORTSCAN_WINDOW = 30        # secondi
PORTSCAN_BLOCK_DURATION = 40

EXT_FLOW_IDLE_TIMEOUT = 20   # secondi: flow EXT, poi ri-ispezione
INT_FLOW_IDLE_TIMEOUT = 200  # secondi: flow INT (più fidato, timeout più lungo)

# =====================================================================
#  REST API Controller
# =====================================================================

FIREWALL_INSTANCE_NAME = 'firewall_app'


class FirewallAPIController(ControllerBase):
    def __init__(self, req, link, data, **config):
        super().__init__(req, link, data, **config)
        self.app = data[FIREWALL_INSTANCE_NAME]

    @route('firewall', '/api/firewall/status', methods=['GET'])
    def status(self, req, **kwargs):
        payload = self.app.get_status()
        return Response(content_type='application/json',
                        body=json.dumps(payload))

    @route('firewall', '/api/firewall/flows', methods=['GET'])
    def flows(self, req, **kwargs):
        dp = self.app.datapath
        if dp:
            try:
                dp.send_msg(dp.ofproto_parser.OFPFlowStatsRequest(dp))
            except Exception:
                pass
        payload = {"flow_stats": self.app.flow_stats}
        return Response(content_type='application/json',
                        body=json.dumps(payload))

    @route('firewall', '/api/firewall/events', methods=['GET'])
    def events(self, req, **kwargs):
        try:
            limit = int(req.params.get('limit', 50))
        except ValueError:
            limit = 50
        limit = max(1, min(limit, 500))
        payload = {"events": list(self.app.event_log)[:limit]}
        return Response(content_type='application/json',
                        body=json.dumps(payload))

    @route('firewall', '/api/firewall/block', methods=['POST'])
    def block(self, req, **kwargs):
        body = self._json(req)
        if isinstance(body, Response):
            return body
        ip = body.get('ip')
        if not ip:
            return Response(status=400, body='Missing ip')
        seconds = int(body.get('seconds', DOS_BLOCK_DURATION))
        self.app.api_block_ip(ip, seconds)
        return Response(content_type='application/json',
                        body=json.dumps({"blocked": ip, "seconds": seconds}))

    @route('firewall', '/api/firewall/unblock', methods=['POST'])
    def unblock(self, req, **kwargs):
        body = self._json(req)
        if isinstance(body, Response):
            return body
        ip = body.get('ip')
        if not ip:
            return Response(status=400, body='Missing ip')
        removed = self.app.api_unblock_ip(ip)
        status = 200 if removed else 404
        return Response(status=status, content_type='application/json',
                        body=json.dumps({"removed": removed, "ip": ip}))

    @route('firewall', '/api/firewall/block_port', methods=['POST'])
    def block_port(self, req, **kwargs):
        body = self._json(req)
        if isinstance(body, Response):
            return body
        protocol = body.get('protocol', 'TCP').upper()
        port = body.get('port')
        if port is None:
            return Response(status=400, body='Missing port')
        scope = body.get('scope', 'mqtt')
        override_allow = bool(body.get('override_allow', False))
        seconds = int(body.get('seconds') or 0)
        self.app.api_block_port(protocol, int(port), scope, override_allow, seconds)
        return Response(content_type='application/json',
                        body=json.dumps({"blocked_port": port, "protocol": protocol}))

    @route('firewall', '/api/firewall/unblock_port', methods=['POST'])
    def unblock_port(self, req, **kwargs):
        body = self._json(req)
        if isinstance(body, Response):
            return body
        protocol = body.get('protocol', 'TCP').upper()
        port = body.get('port')
        if port is None:
            return Response(status=400, body='Missing port')
        scope = body.get('scope', 'mqtt')
        self.app.api_unblock_port(protocol, int(port), scope)
        return Response(content_type='application/json',
                        body=json.dumps({"unblocked_port": port, "protocol": protocol,
                                         "scope": scope}))

    @staticmethod
    def _json(req):
        try:
            return req.json if req.body else {}
        except ValueError:
            return Response(status=400, body='Invalid JSON')


################ Applicazione Ryu principale #####################################
class SDNFirewall(app_manager.RyuApp):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {"wsgi": WSGIApplication}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        wsgi = kwargs["wsgi"]
        wsgi.register(FirewallAPIController, {FIREWALL_INSTANCE_NAME: self})

        self.datapath = None

        # Port mapping dinamico (compilato da PortDescStatsReply)
        self.port_name_to_no = {}   # "eth1" → 3
        self.port_no_to_name = {}   # 3 → "eth1"

        # ARP table dinamica: ip → (mac, port)
        self.arp_table = {}
        self.mac_to_port = {}

        # Interfacce gateway (una per zona)
        self.interfaces = {
            "INT": {
                "ip": ipaddress.ip_address("10.0.10.1"),
                "mac": "02:aa:bb:cc:dd:01",
                "net": ipaddress.ip_network("10.0.10.0/24"),
                "port_names": INT_PORT_NAMES,
            },
            "EXT": {
                "ip": ipaddress.ip_address("10.0.20.1"),
                "mac": "02:aa:bb:cc:dd:02",
                "net": ipaddress.ip_network("10.0.20.0/24"),
                "port_names": EXT_PORT_NAMES,
            },
        }

        # Blocchi IP: ip → {"expires_at": float, "reason": str}
        self.blocked_ips = {}

        # Regole porte bloccate: [{"protocol", "port", "scope", "override_allow", "expires_at"}, ...]
        self.static_port_rules = []

        # MQTT tracking: tentativi e traffico per IP sorgente
        self.mqtt_attempts = defaultdict(lambda: {"allowed": 0, "denied": 0})
        self.mqtt_traffic = defaultdict(lambda: {"packets": 0, "bytes": 0})

        # Sessioni MQTT attive: (src_ip, dst_port) → expires_at
        # Previene MQTT_ACCESS multipli per SYN retransmit / stessa connessione
        self.mqtt_sessions = {}

        # Statistiche flussi OVS (aggiornate ogni 5s via OFPFlowStatsReply)
        self.flow_stats = []

        # DoS detection: ip → deque di timestamp
        self.packet_history = defaultdict(deque)

        # Port-scan detection: ip → {"ports": set, "first_time": float}
        self.port_scan_tracking = defaultdict(
            lambda: {"ports": set(), "first_time": time.time()}
        )

        # Registro eventi (per API)
        # NOTA: NON devo usare "self.events" — è riservato da Ryu internamente!
        self.event_log = deque(maxlen=500)

        # Avvia polling periodico delle statistiche OVS
        hub.spawn(self._poll_flow_stats)

    #############################  Helpers ####################################
    def _log_event(self, event_type, **details):
        event = {"type": event_type, "timestamp": time.time(), **details}
        self.event_log.appendleft(event)
        return event

    def _zone_for_port(self, port_no):
        """Restituisce 'INT' o 'EXT' in base alla porta dello switch."""
        name = self.port_no_to_name.get(port_no)
        if name:
            if name in INT_PORT_NAMES:
                return "INT"
            if name in EXT_PORT_NAMES:
                return "EXT"
        return None

    def _get_out_iface(self, dst_ip):
        """Determina zona/interfaccia di uscita per un IP destinazione."""
        ip = ipaddress.ip_address(dst_ip)
        for zone_name, iface in self.interfaces.items():
            if ip in iface["net"]:
                return zone_name, iface
        return None, None

    def _ports_for_zone(self, zone):
        """Restituisce i numeri di porta OVS per una zona."""
        iface = self.interfaces.get(zone)
        if not iface:
            return set()
        return {self.port_name_to_no[n] for n in iface["port_names"]
                if n in self.port_name_to_no}

    def add_flow(self, datapath, priority, match, actions,
                 buffer_id=None, idle_timeout=0, hard_timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath,
            buffer_id=buffer_id if buffer_id else ofproto.OFP_NO_BUFFER,
            priority=priority,
            match=match,
            instructions=inst,
            idle_timeout=idle_timeout,
            hard_timeout=hard_timeout,
        )
        datapath.send_msg(mod)

    def add_drop_flow(self, datapath, src_ip, duration=120):
        """Installa flow DROP per un IP (actions vuote = drop)."""
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                ipv4_src=src_ip)
        self.add_flow(datapath, 1000, match, [], hard_timeout=duration)
        self.logger.warning("DROP FLOW: %s per %ds", src_ip, duration)

    def remove_drop_flow(self, datapath, src_ip):
        """Rimuove flow DROP per un IP."""
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                ipv4_src=src_ip)
        mod = parser.OFPFlowMod(
            datapath=datapath,
            command=ofproto.OFPFC_DELETE,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            match=match,
        )
        datapath.send_msg(mod)
        self.logger.info("DROP FLOW rimosso: %s", src_ip)

    ####  Blocco / Sblocco IP
    def block_ip(self, datapath, src_ip, duration, reason):
        if src_ip in PROTECTED_IPS:
            self.logger.warning("Blocco IGNORATO per IP protetto: %s (%s)", src_ip, reason)
            return
        self.blocked_ips[src_ip] = {"expires_at": time.time() + duration, "reason": reason}
        self.add_drop_flow(datapath, src_ip, duration)
        self._log_event("BLOCK_IP", ip=src_ip, duration=duration, reason=reason)
        self.logger.warning(">>> BLOCCATO %s per %ds (%s) <<<", src_ip, duration, reason)
        # Reset contatori rilevamento: dopo il blocco il conteggio riparte da zero
        self.packet_history[src_ip].clear()
        if src_ip in self.port_scan_tracking:
            self.port_scan_tracking[src_ip]["ports"].clear()
            self.port_scan_tracking[src_ip]["first_time"] = time.time()

    def is_ip_blocked(self, src_ip):
        """Controlla se IP bloccato; NON rimuove entrate scadute.
        La rimozione + logging UNBLOCK_IP è responsabilità di get_status(),
        per evitare che l'evento venga perso quando un pacchetto arriva
        esattamente mentre il blocco scade."""
        entry = self.blocked_ips.get(src_ip)
        if entry is None:
            return False
        return time.time() < entry["expires_at"]

    ############  API helpers (chiamate dal REST controller) ######################à
    def get_status(self):
        now = time.time()

        # Cleanup IP bloccati scaduti + log evento per ciascuno
        still_blocked = {}
        for ip, d in self.blocked_ips.items():
            if now < d["expires_at"]:
                still_blocked[ip] = d
            else:
                self._log_event("UNBLOCK_IP", ip=ip, reason="expired")
                self.logger.info("IP scaduto, sbloccato: %s", ip)
        self.blocked_ips = still_blocked

        # Rimuovi regole porta scadute
        self.static_port_rules = [
            r for r in self.static_port_rules
            if not r.get("expires_at") or now < r["expires_at"]
        ]

        # Rimuovi sessioni MQTT scadute (cleanup memoria)
        self.mqtt_sessions = {k: v for k, v in self.mqtt_sessions.items() if v > now}

        total_pkts = sum(v["packets"] for v in self.mqtt_traffic.values())
        total_bytes = sum(v["bytes"] for v in self.mqtt_traffic.values())
        top_talkers = sorted(
            [{"ip": ip, "packets": s["packets"], "bytes": s["bytes"]}
             for ip, s in self.mqtt_traffic.items()],
            key=lambda x: x["bytes"], reverse=True
        )[:10]

        # Conta flussi reali dallo switch (se disponibili)
        if self.flow_stats:
            static_flows = [f for f in self.flow_stats if f["priority"] <= 50]
            dynamic_flows = [f for f in self.flow_stats if f["priority"] > 50]
            n_static = len(static_flows)
            n_dynamic_switch = len(dynamic_flows)
        else:
            # Fallback pre-poll: 1 table-miss + 7 inspection = 8 statici
            n_static = 8
            n_dynamic_switch = len(self.blocked_ips) + len(self.static_port_rules)

        allowed_sources = [ip for ip, s in self.mqtt_attempts.items() if s["allowed"] > 0]

        return {
            "blocked_ips": self.blocked_ips,
            "blocked_ports": self.static_port_rules,
            "mqtt_hosts": [MQTT_IP],
            "mqtt_ports": sorted(MQTT_PORTS),
            "mqtt_attempts": {ip: dict(s) for ip, s in self.mqtt_attempts.items()},
            "traffic_to_mqtt": {"packets": total_pkts, "bytes": total_bytes},
            "top_talkers": top_talkers,
            "policy_rules": n_static,
            "active_rules": n_static + n_dynamic_switch,
            "active_dynamic_rules": n_dynamic_switch,
            "allowed_mqtt_sources": allowed_sources,
            "arp_table": {ip: {"mac": mac, "port": port}
                          for ip, (mac, port) in self.arp_table.items()},
            "flow_stats": sorted(self.flow_stats,
                                 key=lambda f: f["priority"], reverse=True),
        }

    def _poll_flow_stats(self):
        """Hub greenlet: richiede statistiche flussi OVS ogni 5 secondi."""
        hub.sleep(3)   # attendo che il datapath sia pronto
        while True:
            dp = self.datapath
            if dp:
                try:
                    parser = dp.ofproto_parser
                    req = parser.OFPFlowStatsRequest(dp)
                    dp.send_msg(req)
                except Exception as e:
                    self.logger.warning("OFPFlowStatsRequest fallito: %s", e)
            hub.sleep(2)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        """Aggiorna self.flow_stats con i dati reali dallo switch."""
        flows = []
        for stat in ev.msg.body:
            try:
                flows.append(self._flow_to_dict(stat))
            except Exception as e:
                self.logger.debug("Errore parsing flow stat: %s", e)
        self.flow_stats = flows
        self.logger.debug("Flow stats ricevute: %d flussi", len(flows))

    def api_block_ip(self, ip, seconds):
        dp = self.datapath
        if dp:
            self.block_ip(dp, ip, seconds, reason="manual")

    def api_unblock_ip(self, ip):
        if ip in self.blocked_ips:
            del self.blocked_ips[ip]
            if self.datapath:
                self.remove_drop_flow(self.datapath, ip)
            self._log_event("UNBLOCK_IP", ip=ip, reason="manual")
            return True
        return False

    def api_block_port(self, protocol, port, scope="mqtt", override_allow=False, seconds=0):
        dp = self.datapath
        if not dp:
            return
        # Evita duplicati (stesso protocol+port+scope)
        for r in self.static_port_rules:
            if (r["protocol"] == protocol and r["port"] == port
                    and r.get("scope") == scope):
                return
        expires_at = (time.time() + seconds) if seconds else 0
        rule = {
            "protocol": protocol, "port": port,
            "scope": scope, "override_allow": override_allow,
            "expires_at": expires_at,
        }
        self.static_port_rules.append(rule)

        parser = dp.ofproto_parser
        ofproto = dp.ofproto
        match_kw = {"eth_type": ether_types.ETH_TYPE_IP}
        if protocol == "TCP":
            match_kw["ip_proto"] = 6
            match_kw["tcp_dst"] = port
        elif protocol == "UDP":
            match_kw["ip_proto"] = 17
            match_kw["udp_dst"] = port
        # scope="mqtt" → restringe solo al traffico verso il broker
        if scope == "mqtt":
            match_kw["ipv4_dst"] = MQTT_IP
        match = parser.OFPMatch(**match_kw)
        hard_timeout = seconds if seconds else 0

        # override_allow=True → prio 1100 (sopra tutto, incluso IP-drop a 1000)
        # override_allow=False → prio 900 (sopra forwarding/deny ma non IP-drop)
        priority = 1100 if override_allow else 900
        self.add_flow(dp, priority, match, [], hard_timeout=hard_timeout)

        if override_allow:
            # Elimina anche i forwarding flow già installati (prio 60) per questa porta
            mod = parser.OFPFlowMod(
                datapath=dp, command=ofproto.OFPFC_DELETE,
                priority=60,
                out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY,
                match=match)
            dp.send_msg(mod)

        self._log_event("PORT_BLOCKED", protocol=protocol, port=port,
                        scope=scope, override=override_allow)
        self.logger.warning("PORT BLOCKED: %s/%d scope=%s override=%s",
                            protocol, port, scope, override_allow)

    def api_unblock_port(self, protocol, port, scope="mqtt"):
        self.static_port_rules = [
            r for r in self.static_port_rules
            if not (r["protocol"] == protocol and r["port"] == port
                    and r.get("scope") == scope)
        ]
        dp = self.datapath
        if dp:
            parser = dp.ofproto_parser
            ofproto = dp.ofproto
            match_kw = {"eth_type": ether_types.ETH_TYPE_IP}
            if protocol == "TCP":
                match_kw["ip_proto"] = 6
                match_kw["tcp_dst"] = port
            elif protocol == "UDP":
                match_kw["ip_proto"] = 17
                match_kw["udp_dst"] = port
            if scope == "mqtt":
                match_kw["ipv4_dst"] = MQTT_IP
            match = parser.OFPMatch(**match_kw)
            mod = parser.OFPFlowMod(
                datapath=dp, command=ofproto.OFPFC_DELETE,
                out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY,
                match=match)
            dp.send_msg(mod)
        self._log_event("PORT_UNBLOCKED", protocol=protocol, port=port, scope=scope)

    ######## Rilevamento DoS (sliding window su packet-in) ################

    def detect_dos(self, datapath, src_ip):
        """
        Sliding-window DoS detection: conta i packet-in per IP.
        Triggera quando len(history) >= DOS_THRESHOLD entro DOS_WINDOW secondi.
        """
        now = time.time()
        history = self.packet_history[src_ip]

        # Pruning: rimuovi timestamp fuori finestra
        while history and (now - history[0]) > DOS_WINDOW:
            history.popleft()
        history.append(now)

        if len(history) >= DOS_THRESHOLD:
            time_span = history[-1] - history[0]
            self.logger.warning("DoS RILEVATO da %s: %d pkt in %.1fs",
                                src_ip, len(history), time_span)
            self._log_event("DOS_DETECTED", src_ip=src_ip,
                            packets=len(history), window=time_span)
            self.block_ip(datapath, src_ip, DOS_BLOCK_DURATION, "dos")
            return True
        return False

    #############  Rilevamento Port-Scan ############################à
    def detect_port_scan(self, datapath, src_ip, dst_port):
        """
        Traccia porte distinte per IP in una finestra.
        Se porte distinte >= soglia → blocco.
        """
        now = time.time()
        tracking = self.port_scan_tracking[src_ip]

        # Reset finestra se scaduta
        if now - tracking["first_time"] > PORTSCAN_WINDOW:
            tracking["ports"].clear()
            tracking["first_time"] = now

        tracking["ports"].add(dst_port)

        if len(tracking["ports"]) >= PORTSCAN_THRESHOLD:
            self.logger.warning("PORT SCAN da %s: %d porte distinte",
                                src_ip, len(tracking["ports"]))
            self._log_event("PORTSCAN_DETECTED", src_ip=src_ip,
                            unique_ports=len(tracking["ports"]))
            self.block_ip(datapath, src_ip, PORTSCAN_BLOCK_DURATION, "port_scan")
            return True
        return False

    ################  Switch features → flow iniziali  ##################
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        self.datapath = datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # 0) Table-miss → controller
        self.add_flow(datapath, 0, parser.OFPMatch(),
                      [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                              ofproto.OFPCML_NO_BUFFER)])
        self.logger.info("Table-miss installato")

        # Richiedo descrizione porte per scoprire il mapping eth→numero
        datapath.send_msg(parser.OFPPortDescStatsRequest(datapath, 0))

    @set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)
    def port_desc_handler(self, ev):
        """Scopre i numeri di porta OVS e installa i flow statici."""
        self.port_name_to_no.clear()
        self.port_no_to_name.clear()

        for p in ev.msg.body:
            name = p.name
            if isinstance(name, bytes):
                name = name.decode('utf-8', errors='ignore').rstrip('\x00')
            self.port_name_to_no[name] = p.port_no
            self.port_no_to_name[p.port_no] = name
            # Normalizza "s1-eth3" → "eth3"
            if "-eth" in name:
                suffix = name.split("-eth", 1)[1]
                norm = f"eth{suffix}"
                self.port_name_to_no[norm] = p.port_no
                self.port_no_to_name[p.port_no] = norm

        self.logger.info("Port map: %s", self.port_name_to_no)
        self._install_static_flows()

    def _install_static_flows(self):
        """Installa flow statici dopo il discovery delle porte."""
        datapath = self.datapath
        if not datapath:
            return
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Ispezione traffico IP da TUTTE le zone (priorità 50)
        for zone_name in ("INT", "EXT"):
            zone_port_nos = self._ports_for_zone(zone_name)
            for port_no in sorted(zone_port_nos):
                match = parser.OFPMatch(
                    in_port=port_no,
                    eth_type=ether_types.ETH_TYPE_IP,
                )
                self.add_flow(datapath, 50, match,
                              [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                                      ofproto.OFPCML_NO_BUFFER)])
            self.logger.info("Ispezione %s installata su porte OVS %s",
                             zone_name, zone_port_nos)

    ###############  ARP handling ################################à

    def _handle_arp(self, msg, in_port, pkt, datapath):
        ofp = datapath.ofproto
        parser = datapath.ofproto_parser
        arp_pkt = pkt.get_protocol(arp.arp)

        src_ip = arp_pkt.src_ip
        src_mac = arp_pkt.src_mac
        dst_ip = arp_pkt.dst_ip

        # Apprendi IP → (MAC, porta)
        self.arp_table[src_ip] = (src_mac, in_port)
        self.logger.info("ARP learn: %s = %s (porta %d)", src_ip, src_mac, in_port)

        if arp_pkt.opcode == arp.ARP_REQUEST:
            # È una richiesta per il gateway?
            for zone_name, iface in self.interfaces.items():
                if (iface["ip"].compressed == dst_ip
                        and in_port in self._ports_for_zone(zone_name)):
                    # Rispondi con il MAC del gateway per questa zona
                    self._send_arp_reply(datapath, parser, ofp,
                                         src_mac, src_ip,
                                         iface["mac"], dst_ip, in_port)
                    return

            # È una richiesta per un IP dell'ALTRA zona?
            # rispondo col MAC del gateway locale (proxy ARP)
            src_zone = self._zone_for_port(in_port)
            dst_zone, dst_iface = self._get_out_iface(dst_ip)
            if dst_zone and dst_zone != src_zone:
                # Rispondo con il MAC del gateway della zona sorgente
                src_iface = self.interfaces.get(src_zone)
                if src_iface:
                    self._send_arp_reply(datapath, parser, ofp,
                                         src_mac, src_ip,
                                         src_iface["mac"], dst_ip, in_port)
                    return

            # Richiesta ARP intra-zona per host sconosciuto → flood nella zona
            self.logger.info("ARP flood nella zona")
            zone = self._zone_for_port(in_port)
            self._flood_zone(datapath, parser, ofp, zone, in_port, msg.data)

        elif arp_pkt.opcode == arp.ARP_REPLY:
            self.logger.info("ARP reply: %s = %s", src_ip, src_mac)
            # Inoltra la reply al destinatario
            dst_entry = self.arp_table.get(dst_ip)
            if dst_entry:
                dst_mac_saved, dst_port = dst_entry
                actions = [parser.OFPActionOutput(dst_port)]
                datapath.send_msg(parser.OFPPacketOut(
                    datapath=datapath, buffer_id=ofp.OFP_NO_BUFFER,
                    in_port=in_port, actions=actions, data=msg.data))
            else:
                zone = self._zone_for_port(in_port)
                self._flood_zone(datapath, parser, ofp, zone, in_port, msg.data)

    def _send_arp_reply(self, datapath, parser, ofp,
                        dst_mac, dst_ip, src_mac, src_ip, out_port):
        p = packet.Packet()
        p.add_protocol(ethernet.ethernet(
            dst=dst_mac, src=src_mac, ethertype=ether.ETH_TYPE_ARP))
        p.add_protocol(arp.arp(
            opcode=arp.ARP_REPLY,
            src_mac=src_mac, src_ip=src_ip,
            dst_mac=dst_mac, dst_ip=dst_ip))
        p.serialize()
        datapath.send_msg(parser.OFPPacketOut(
            datapath=datapath, buffer_id=ofp.OFP_NO_BUFFER,
            in_port=ofp.OFPP_CONTROLLER,
            actions=[parser.OFPActionOutput(out_port)],
            data=p.data))

    def _send_arp_request(self, datapath, dst_ip, out_zone, out_iface):
        """Invia ARP request dal gateway per scoprire un host."""
        parser = datapath.ofproto_parser
        ofp = datapath.ofproto

        p = packet.Packet()
        p.add_protocol(ethernet.ethernet(
            dst="ff:ff:ff:ff:ff:ff",
            src=out_iface["mac"],
            ethertype=ether.ETH_TYPE_ARP))
        p.add_protocol(arp.arp(
            opcode=arp.ARP_REQUEST,
            src_mac=out_iface["mac"],
            src_ip=out_iface["ip"].compressed,
            dst_mac="00:00:00:00:00:00",
            dst_ip=dst_ip))
        p.serialize()

        # Flood su tutte le porte della zona
        for port_no in sorted(self._ports_for_zone(out_zone)):
            datapath.send_msg(parser.OFPPacketOut(
                datapath=datapath, buffer_id=ofp.OFP_NO_BUFFER,
                in_port=ofp.OFPP_CONTROLLER,
                actions=[parser.OFPActionOutput(port_no)],
                data=p.data))

    def _flow_to_dict(self, stat):
        """Converte OFPFlowStats in un dict JSON-serializzabile."""
        safe_match = {}
        for k, v in stat.match.items():
            if k == 'eth_type' and isinstance(v, int):
                safe_match[k] = hex(v)
            elif k == 'ip_proto' and isinstance(v, int):
                safe_match[k] = {6: 'TCP', 17: 'UDP'}.get(v, v)
            elif isinstance(v, (int, str, float, bool)):
                safe_match[k] = v
            else:
                safe_match[k] = str(v)

        ctrl_port = (self.datapath.ofproto.OFPP_CONTROLLER
                     if self.datapath else 0xFFFFFFFD)
        action_list = []
        for inst in stat.instructions:
            acts = getattr(inst, 'actions', [])
            if not acts:
                continue
            for act in acts:
                if hasattr(act, 'port'):
                    p = act.port
                    if p == ctrl_port:
                        action_list.append("→CTRL")
                    else:
                        name = self.port_no_to_name.get(p, f"p{p}")
                        action_list.append(f"OUT:{name}")
                else:
                    cls = type(act).__name__.replace('OFPAction', '')
                    action_list.append(cls)
        if not action_list:
            action_list = ["DROP"]

        return {
            "priority": stat.priority,
            "idle_timeout": stat.idle_timeout,
            "hard_timeout": stat.hard_timeout,
            "duration_sec": stat.duration_sec,
            "packet_count": stat.packet_count,
            "byte_count": stat.byte_count,
            "match": safe_match,
            "actions": action_list,
            "table_id": stat.table_id,
        }

    def _flood_zone(self, datapath, parser, ofp, zone, in_port, data):
        """Flood un pacchetto su tutte le porte della zona tranne quella sorgente."""
        ports = self._ports_for_zone(zone)
        actions = [parser.OFPActionOutput(p)
                   for p in sorted(ports) if p != in_port]
        if actions:
            datapath.send_msg(parser.OFPPacketOut(
                datapath=datapath, buffer_id=ofp.OFP_NO_BUFFER,
                in_port=in_port, actions=actions, data=data))

    ################  Packet-In: pipeline principale  #############################
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        parser = datapath.ofproto_parser
        ofp = datapath.ofproto
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        # ---------- ARP ----------
        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            self._handle_arp(msg, in_port, pkt, datapath)
            return

        # ---------- IPv4 ----------
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        if not ipv4_pkt:
            # Non-IP: L2 switching semplice
            self._handle_l2(msg, in_port, eth, datapath)
            return

        src_ip = ipv4_pkt.src
        dst_ip = ipv4_pkt.dst
        src_zone = self._zone_for_port(in_port)

        # ---------- IP bloccato → drop ----------
        if self.is_ip_blocked(src_ip):
            self.logger.debug("DROP (bloccato): %s", src_ip)
            return

        # ---------- Estrai porta TCP/UDP ----------
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        udp_pkt = pkt.get_protocol(udp.udp)
        dst_port = None
        if tcp_pkt:
            dst_port = tcp_pkt.dst_port
        elif udp_pkt:
            dst_port = udp_pkt.dst_port

        # SYN flag: solo i pacchetti SYN avviano nuove connessioni
        is_syn = tcp_pkt is not None and bool(tcp_pkt.bits & 0x002)

        # ---------- Regole statiche porte ----------
        if self._matches_port_rule(tcp_pkt, udp_pkt, dst_ip):
            self.logger.warning("STATIC PORT DROP: %s → %s porta %s",
                                src_ip, dst_ip, dst_port)
            return

        # ---------- Ispezione DoS e PortScan (solo su SYN) ----------
        # Limitare ai SYN evita che RST/SYN+ACK di risposta vengano contati
        # come DoS/scan della vittima (che altrimenti verrebbe bloccata al posto
        # dell'attaccante).
        if is_syn:
            if self.detect_dos(datapath, src_ip):
                return
            if self.detect_port_scan(datapath, src_ip, dst_port):
                return

        # ---------- Traffico verso MQTT: policy check ----------
        if dst_ip == MQTT_IP and tcp_pkt:
            self._handle_mqtt(msg, datapath, parser, ofp, in_port,
                              src_zone, src_ip, dst_port, tcp_pkt, is_syn)
            return

        # ---------- L3 Routing ----------
        self._handle_l3(msg, datapath, parser, ofp, in_port,
                        src_ip, dst_ip, src_zone, tcp_pkt, udp_pkt)

    ################  MQTT policy #############################

    def _handle_mqtt(self, msg, datapath, parser, ofp, in_port,
                     src_zone, src_ip, dst_port, tcp_pkt, is_syn):
        """
        Policy MQTT:
        - Porta non MQTT → deny (drop flow, solo per non-SYN)
        - INT → flow a priorità 60, idle_timeout 200s
        - EXT → flow a priorità 60, idle_timeout 20s
        """
        tcp_flags = _tcp_flags_str(tcp_pkt.bits)

        # Porta non autorizzata → deny.
        # Il flow viene installato SOLO su pacchetti non-SYN: se fosse installato
        # sul SYN, tutti i SYN successivi con la stessa tcp_src (comune con hping3)
        # verrebbero droppati dall'OVS senza raggiungere il controller,
        # rendendo il DoS non rilevabile.
        if dst_port not in MQTT_PORTS:
            self.logger.warning("MQTT DENY: %s porta %d (non MQTT)",
                                src_ip, dst_port)
            self.mqtt_attempts[src_ip]["denied"] += 1
            self._log_event("MQTT_DENIED", src_ip=src_ip,
                            dst_port=dst_port, reason="porta_non_mqtt",
                            flags=tcp_flags)
            if not is_syn:
                match = parser.OFPMatch(
                    eth_type=ether_types.ETH_TYPE_IP, ip_proto=6,
                    ipv4_src=src_ip, ipv4_dst=MQTT_IP,
                    tcp_src=tcp_pkt.src_port, tcp_dst=dst_port)
                self.add_flow(datapath, 100, match, [],
                              idle_timeout=30, hard_timeout=60)
            return

        # Timeout differenziato per zona
        if src_zone is None:
            self.logger.warning(
                "MQTT: zona sconosciuta per porta OVS %d (ip=%s) — "
                "port_no_to_name=%s. Uso timeout EXT conservativo.",
                in_port, src_ip, dict(self.port_no_to_name))
        timeout = INT_FLOW_IDLE_TIMEOUT if src_zone == "INT" else EXT_FLOW_IDLE_TIMEOUT

        # Log accesso PRIMA del check ARP: quando N SYN paralleli arrivano prima
        # che l'ARP sia risolto, tutti tornano per ARP miss ma MQTT_ACCESS viene
        # comunque registrato sul primo (deduplicato dai successivi tramite mqtt_sessions).
        now = time.time()
        flow_key = (src_ip, dst_port)
        is_new_session = (flow_key not in self.mqtt_sessions
                          or now > self.mqtt_sessions[flow_key])
        if is_new_session:
            self.mqtt_sessions[flow_key] = now + timeout
            self.mqtt_attempts[src_ip]["allowed"] += 1
            self._log_event("MQTT_ACCESS", src_ip=src_ip, dst_port=dst_port,
                            zone=src_zone, flags=tcp_flags)

        # Verifica ARP: se non risolto, invia richiesta e attendi il prossimo pacchetto
        mqtt_entry = self.arp_table.get(MQTT_IP)
        if not mqtt_entry:
            mqtt_zone, mqtt_iface = self._get_out_iface(MQTT_IP)
            if mqtt_iface:
                self._send_arp_request(datapath, MQTT_IP, mqtt_zone, mqtt_iface)
            return

        mqtt_mac, mqtt_port = mqtt_entry
        src_entry = self.arp_table.get(src_ip)

        # Traffico sempre aggiornato (ogni packet-in della connessione)
        self.mqtt_traffic[src_ip]["packets"] += 1
        self.mqtt_traffic[src_ip]["bytes"] += len(msg.data)

        # Flow di forwarding installati SOLO su pacchetti non-SYN:
        # ogni SYN raggiunge sempre il controller → DoS rilevabile anche quando
        # hping3 usa la stessa source port su tutti i processi paralleli.
        tcp_src_port = tcp_pkt.src_port

        if src_zone == "INT":
            # ---- INTERNO: stessa zona, no MAC rewrite ----
            actions_fwd = [parser.OFPActionOutput(mqtt_port)]
            match_fwd = parser.OFPMatch(
                in_port=in_port, eth_type=ether_types.ETH_TYPE_IP,
                ip_proto=6, ipv4_src=src_ip, ipv4_dst=MQTT_IP,
                tcp_src=tcp_src_port, tcp_dst=dst_port)

            if not is_syn:
                # Connessione stabilita: installa flow per efficienza
                self.add_flow(datapath, 60, match_fwd, actions_fwd,
                              idle_timeout=timeout)
                if src_entry:
                    src_mac, src_port = src_entry
                    actions_rev = [parser.OFPActionOutput(src_port)]
                    match_rev = parser.OFPMatch(
                        in_port=mqtt_port, eth_type=ether_types.ETH_TYPE_IP,
                        ip_proto=6, ipv4_src=MQTT_IP, ipv4_dst=src_ip,
                        tcp_src=dst_port, tcp_dst=tcp_src_port)
                    self.add_flow(datapath, 60, match_rev, actions_rev,
                                  idle_timeout=timeout)
            # SYN: nessun flow → il prossimo SYN (anche stesso tcp_src) colpisce
            # sempre il controller → rilevamento DoS affidabile

            datapath.send_msg(parser.OFPPacketOut(
                datapath=datapath, buffer_id=ofp.OFP_NO_BUFFER,
                in_port=in_port, actions=actions_fwd, data=msg.data))

        else:
            # ---- ESTERNO: cross-zona, MAC rewrite ----
            int_iface = self.interfaces["INT"]
            ext_iface = self.interfaces["EXT"]

            actions_fwd = [
                parser.OFPActionSetField(eth_src=int_iface["mac"]),
                parser.OFPActionSetField(eth_dst=mqtt_mac),
                parser.OFPActionOutput(mqtt_port),
            ]
            match_fwd = parser.OFPMatch(
                in_port=in_port, eth_type=ether_types.ETH_TYPE_IP,
                ip_proto=6, ipv4_src=src_ip, ipv4_dst=MQTT_IP,
                tcp_src=tcp_src_port, tcp_dst=dst_port)

            if not is_syn:
                # Connessione stabilita: installa flow per efficienza
                self.add_flow(datapath, 60, match_fwd, actions_fwd,
                              idle_timeout=timeout)
                if src_entry:
                    src_mac, src_port_no = src_entry
                    actions_rev = [
                        parser.OFPActionSetField(eth_src=ext_iface["mac"]),
                        parser.OFPActionSetField(eth_dst=src_mac),
                        parser.OFPActionOutput(src_port_no),
                    ]
                    match_rev = parser.OFPMatch(
                        in_port=mqtt_port, eth_type=ether_types.ETH_TYPE_IP,
                        ip_proto=6, ipv4_src=MQTT_IP, ipv4_dst=src_ip,
                        tcp_src=dst_port, tcp_dst=tcp_src_port)
                    self.add_flow(datapath, 60, match_rev, actions_rev,
                                  idle_timeout=timeout)

            datapath.send_msg(parser.OFPPacketOut(
                datapath=datapath, buffer_id=ofp.OFP_NO_BUFFER,
                in_port=in_port, actions=actions_fwd, data=msg.data))

    ###############  L3 Routing (traffico generico non-MQTT) ##########################à

    def _handle_l3(self, msg, datapath, parser, ofp, in_port,
                   src_ip, dst_ip, src_zone, tcp_pkt=None, udp_pkt=None):
        """Routing L3 generico tra le due zone."""

        dst_zone, dst_iface = self._get_out_iface(dst_ip)
        if dst_zone is None:
            self.logger.info("Nessuna rotta per %s, drop", dst_ip)
            return

        # Timeout differenziato per zona sorgente
        timeout = INT_FLOW_IDLE_TIMEOUT if src_zone == "INT" else EXT_FLOW_IDLE_TIMEOUT

        # Match L4 per-connessione: garantisce che ogni nuovo flusso TCP/UDP
        # raggiunga il controller (necessario per DoS detection affidabile)
        extra_fwd = {}
        extra_rev = {}
        if tcp_pkt:
            extra_fwd = {"ip_proto": 6,
                         "tcp_src": tcp_pkt.src_port, "tcp_dst": tcp_pkt.dst_port}
            extra_rev = {"ip_proto": 6,
                         "tcp_src": tcp_pkt.dst_port, "tcp_dst": tcp_pkt.src_port}
        elif udp_pkt:
            extra_fwd = {"ip_proto": 17,
                         "udp_src": udp_pkt.src_port, "udp_dst": udp_pkt.dst_port}
            extra_rev = {"ip_proto": 17,
                         "udp_src": udp_pkt.dst_port, "udp_dst": udp_pkt.src_port}

        # Stessa zona → L2 switching
        if dst_zone == src_zone:
            dst_entry = self.arp_table.get(dst_ip)
            if dst_entry:
                dst_mac, dst_host_port = dst_entry
                actions = [parser.OFPActionOutput(dst_host_port)]
                match = parser.OFPMatch(
                    in_port=in_port, eth_type=ether_types.ETH_TYPE_IP,
                    ipv4_src=src_ip, ipv4_dst=dst_ip, **extra_fwd)
                self.add_flow(datapath, 60, match, actions,
                              idle_timeout=timeout)
                data = msg.data if msg.buffer_id == ofp.OFP_NO_BUFFER else None
                datapath.send_msg(parser.OFPPacketOut(
                    datapath=datapath, buffer_id=msg.buffer_id,
                    in_port=in_port, actions=actions, data=data))
            else:
                self._flood_zone(datapath, parser, ofp, src_zone,
                                 in_port, msg.data)
            return

        # Cross-zona: routing L3 con MAC rewrite
        dst_entry = self.arp_table.get(dst_ip)
        if not dst_entry:
            self.logger.info("ARP request per %s", dst_ip)
            self._send_arp_request(datapath, dst_ip, dst_zone, dst_iface)
            return

        dst_mac, dst_host_port = dst_entry

        actions = [
            parser.OFPActionSetField(eth_src=dst_iface["mac"]),
            parser.OFPActionSetField(eth_dst=dst_mac),
            parser.OFPActionOutput(dst_host_port),
        ]

        # Forward: src → dst
        match = parser.OFPMatch(
            in_port=in_port, eth_type=ether_types.ETH_TYPE_IP,
            ipv4_src=src_ip, ipv4_dst=dst_ip, **extra_fwd)
        self.add_flow(datapath, 60, match, actions,
                      idle_timeout=timeout)

        # Reverse: dst → src
        # Non installo il flow reverse quando src_ip è un IP protetto (es. MQTT_IP):
        # il flow reverse (prio 60) sovrascrive l'ispezione (prio 50) e intercetta
        # i SYN successivi di un attaccante verso MQTT_IP, impedendo il DoS detection.
        src_entry = self.arp_table.get(src_ip)
        src_iface = self.interfaces.get(src_zone)
        if src_entry and src_iface and src_ip not in PROTECTED_IPS:
            src_mac, src_host_port = src_entry
            rev_timeout = INT_FLOW_IDLE_TIMEOUT if dst_zone == "INT" else EXT_FLOW_IDLE_TIMEOUT
            actions_rev = [
                parser.OFPActionSetField(eth_src=src_iface["mac"]),
                parser.OFPActionSetField(eth_dst=src_mac),
                parser.OFPActionOutput(src_host_port),
            ]
            match_rev = parser.OFPMatch(
                in_port=dst_host_port, eth_type=ether_types.ETH_TYPE_IP,
                ipv4_src=dst_ip, ipv4_dst=src_ip, **extra_rev)
            self.add_flow(datapath, 60, match_rev, actions_rev,
                          idle_timeout=rev_timeout)

        # Inoltra pacchetto corrente (gestisce sia pacchetti bufferizzati
        # dallo switch sia pacchetti inviati direttamente con i dati)
        data = msg.data if msg.buffer_id == ofp.OFP_NO_BUFFER else None
        datapath.send_msg(parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id,
            in_port=in_port, actions=actions, data=data))

    ##################  L2 switching (traffico non-IP) #######################à

    def _handle_l2(self, msg, in_port, eth, datapath):
        """L2 learning switch per traffico non-IP."""
        ofp = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id

        self.mac_to_port.setdefault(dpid, {})
        src = eth.src
        dst = eth.dst
        self.mac_to_port[dpid][src] = in_port

        out_port = self.mac_to_port[dpid].get(dst, ofp.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofp.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_src=src, eth_dst=dst)
            self.add_flow(datapath, 1, match, actions)

        data = msg.data if msg.buffer_id == ofp.OFP_NO_BUFFER else None
        datapath.send_msg(parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id,
            in_port=in_port, actions=actions, data=data))

    ##############àà#  Check regole statiche porte #################à#

    def _matches_port_rule(self, tcp_pkt, udp_pkt, dst_ip):
        """Controlla se il pacchetto matcha una regola statica porta.
        Tiene conto dello scope: 'mqtt' → solo traffico verso MQTT_IP."""
        for rule in self.static_port_rules:
            if rule.get("scope") == "mqtt" and dst_ip != MQTT_IP:
                continue
            proto = rule["protocol"]
            port = rule["port"]
            if proto == "TCP" and tcp_pkt and tcp_pkt.dst_port == port:
                return True
            if proto == "UDP" and udp_pkt and udp_pkt.dst_port == port:
                return True
        return False
