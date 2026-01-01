from ipaddress import ip_address, ip_network
from typing import Dict, Optional

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER, set_ev_cls
from ryu.lib import hub
from ryu.lib.packet import packet, ethernet, ipv4, tcp, arp
from ryu.ofproto import ofproto_v1_3
from ryu.app.wsgi import WSGIApplication

from firewall_api import FIREWALL_INSTANCE_NAME, FirewallAPIController
from firewall_logic import FirewallLogic
from of_helpers import add_flow, delete_flows, add_drop_flow_for_port, delete_drop_flow_for_port

# ---------- Network definitions ----------
HOSTS = {
    "c1": {"ip": "10.0.10.11", "mac": "02:00:00:10:00:11"},
    "c2": {"ip": "10.0.10.12", "mac": "02:00:00:10:00:12"},
    "c3": {"ip": "10.0.10.13", "mac": "02:00:00:10:00:13"},
    "mqtt": {"ip": "10.0.10.20", "mac": "02:00:00:10:00:20"},
    "a1": {"ip": "10.0.20.31", "mac": "02:00:00:20:00:31"},
    "a2": {"ip": "10.0.20.32", "mac": "02:00:00:20:00:32"},
    "a3": {"ip": "10.0.20.33", "mac": "02:00:00:20:00:33"},
}

MQTT_IP = HOSTS["mqtt"]["ip"]
MQTT_HOSTS = [MQTT_IP]
MQTT_PORTS = [1883, 8883]

ALLOWED_INT_SUBNET = ip_network("10.0.10.0/24")
EXT_SUBNET = ip_network("10.0.20.0/24")

GATEWAY_IPS = ["10.0.10.1", "10.0.20.1"]
GATEWAY_MAC = "02:aa:bb:cc:dd:01"

# Port mapping by design (eth1..eth4 internal, eth5..eth7 external)
# We still learn real ofport values via PortDescStatsReply and keep fallback.
INT_PORT_NAMES = {"eth1", "eth2", "eth3", "eth4"}
EXT_PORT_NAMES = {"eth5", "eth6", "eth7"}

# Static hint (works if your OVS ofport numbers match ethX order; we override with port-desc)
HOST_PORTS: Dict[str, str] = {
    "10.0.10.11": "eth1",
    "10.0.10.12": "eth2",
    "10.0.10.13": "eth3",
    "10.0.10.20": "eth4",
    "10.0.20.31": "eth5",
    "10.0.20.32": "eth6",
    "10.0.20.33": "eth7",
}

# ---------- Detection thresholds ----------
PORTSCAN_THRESHOLD = 6
PORTSCAN_WINDOW = 10
PORTSCAN_BLOCK_SECONDS = 30

DOS_THRESHOLD = 160
DOS_WINDOW = 5
DOS_BLOCK_SECONDS = 60

DEFAULT_BLOCK_SECONDS = 60
DEFAULT_PORT_BLOCK_PRIORITY = 700
OVERRIDE_PORT_BLOCK_PRIORITY = 850

MIRROR_LEN = 128  # bytes to controller


class SDNFirewall(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {"wsgi": WSGIApplication}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        wsgi = kwargs["wsgi"]

        self.datapath = None
        self.gateway_mac = GATEWAY_MAC
        self.gateway_ips = set(GATEWAY_IPS)

        # port maps
        self.port_name_to_no: Dict[str, int] = {f"eth{i}": i for i in range(1, 8)}
        self.port_no_to_name: Dict[int, str] = {i: f"eth{i}" for i in range(1, 8)}

        # L2 learning per-zone
        self.mac_to_port: Dict[str, int] = {}          # MAC -> ofport
        self.mac_to_zone: Dict[str, str] = {}          # MAC -> "INT"/"EXT"
        self.ip_to_mac: Dict[str, str] = {**{ip: GATEWAY_MAC for ip in GATEWAY_IPS}, **{v["ip"]: v["mac"] for v in HOSTS.values()}}

        self.policy_installed = False

        self.logic = FirewallLogic(
            mqtt_hosts=MQTT_HOSTS,
            allowed_mqtt_sources=[],
            allowed_subnet=str(ALLOWED_INT_SUBNET),
            mqtt_ports=MQTT_PORTS,
            portscan_threshold=PORTSCAN_THRESHOLD,
            portscan_window=PORTSCAN_WINDOW,
            dos_threshold=DOS_THRESHOLD,
            dos_window=DOS_WINDOW,
            block_seconds=DEFAULT_BLOCK_SECONDS,
            scan_block_seconds=PORTSCAN_BLOCK_SECONDS,
        )

        wsgi.register(FirewallAPIController, {FIREWALL_INSTANCE_NAME: self})
        self.monitor_thread = hub.spawn(self._monitor)

    # ------------------ API helpers ------------------
    def api_status(self):
        try:
            status = self.logic.get_status()
            status.update({
                "active_rules": self._estimate_active_rules(),
                "policy_rules": self._policy_rule_count(),
            })
            return status
        except Exception as e:
            self.logger.exception("status error")
            return {"error": str(e)}

    def api_events(self, limit: int = 200):
        return {"events": self.logic.get_recent_events(limit)}

    def api_block_ip(self, ip: str, seconds=None):
        dp = self.datapath
        if not dp:
            return {"error": "datapath not ready"}
        expires = self._block_ip(dp, ip, seconds or DEFAULT_BLOCK_SECONDS, reason="MANUAL_BLOCK", target="MQTT")
        return {"ip": ip, "expires_at": expires}

    def api_unblock_ip(self, ip: str):
        removed = self.logic.unblock_ip(ip, reason="MANUAL")
        if not removed:
            return {"removed": False, "ip": ip}
        dp = self.datapath
        if dp:
            match = dp.ofproto_parser.OFPMatch(eth_type=0x0800, ipv4_src=ip)
            delete_flows(dp, match)
            self.policy_installed = False
        return {"removed": True, "ip": ip}

    def api_block_port(self, port: int, scope: str = "mqtt", seconds=None, override_allow: bool = False):
        dp = self.datapath
        if not dp:
            return {"error": "datapath not ready"}
        duration = seconds or DEFAULT_BLOCK_SECONDS
        expires = self._block_port(dp, port, scope, duration, override_allow, reason="MANUAL_PORT_BLOCK")
        return {
            "port": port,
            "scope": scope,
            "expires_at": expires,
            "override_allow": bool(override_allow),
            "installed": True
        }

    def api_unblock_port(self, port: int, scope: str = "mqtt", override_allow=None):
        removed_entries = self.logic.unblock_port(port, scope, override_allow, reason="MANUAL_PORT_UNBLOCK")
        if not removed_entries:
            return {"removed": False, "port": port, "scope": scope}
        dp = self.datapath
        if dp:
            targets = MQTT_HOSTS if scope == "mqtt" else [None]
            for target in targets:
                delete_drop_flow_for_port(dp, port, scope, mqtt_ip=target)
        return {"removed": True, "port": port, "scope": scope}

    # ------------------ OpenFlow setup ------------------
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp = ev.msg.datapath
        self.datapath = dp
        parser = dp.ofproto_parser
        ofp = dp.ofproto

        # Table-miss drop (default deny)
        add_flow(dp, 0, parser.OFPMatch(), [])

        # Ask port descriptions (map ethX -> ofport)
        dp.send_msg(parser.OFPPortDescStatsRequest(dp, 0))
        # Try static flows with fallback port map
        self._install_static_flows()

        self.logger.info("Switch %s configured (miss->controller, zone learning, MQTT policy)", dp.id)

    @set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)
    def port_desc_handler(self, ev):
        self.port_no_to_name.clear()
        for p in ev.msg.body:
            self.port_name_to_no[p.name] = p.port_no
            self.port_no_to_name[p.port_no] = p.name
        self.logger.info("Port map learned: %s", self.port_name_to_no)
        self._install_static_flows()

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change_handler(self, ev):
        dp = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.datapath = dp
        elif ev.state == DEAD_DISPATCHER and self.datapath and dp.id == self.datapath.id:
            self.datapath = None
            self.policy_installed = False
            self.mac_to_port.clear()
            self.mac_to_zone.clear()

    # ------------------ Monitor / cleanup ------------------
    def _monitor(self):
        while True:
            hub.sleep(5)
            dp = self.datapath
            if not dp:
                continue

            expired_ips = self.logic.cleanup_expired_blocks()
            for ip in expired_ips:
                match = dp.ofproto_parser.OFPMatch(eth_type=0x0800, ipv4_src=ip)
                delete_flows(dp, match)
                self.logic.log_event("UNBLOCK_IP", ip=ip, reason="timeout")

            expired_ports = self.logic.cleanup_expired_port_blocks()
            for entry in expired_ports:
                targets = MQTT_HOSTS if entry["scope"] == "mqtt" else [None]
                for target in targets:
                    delete_drop_flow_for_port(dp, entry["port"], entry["scope"], mqtt_ip=target)
                self.logic.log_event(
                    "PORT_UNBLOCKED",
                    port=entry["port"],
                    scope=entry["scope"],
                    override_allow=entry.get("override_allow", False),
                    reason="timeout",
                )

            dp.send_msg(dp.ofproto_parser.OFPFlowStatsRequest(dp))

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        self.logic.update_flow_counters(ev.msg.body)

    # ------------------ Packet processing ------------------
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        parser = dp.ofproto_parser
        ofp = dp.ofproto
        in_port = msg.match["in_port"]

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if not eth:
            return
        if eth.ethertype == 0x88cc:  # LLDP
            return

        src_mac = eth.src.lower()
        dst_mac = eth.dst.lower()

        zone = self._zone_for_in_port(in_port)
        if zone is None:
            # unknown port -> safest drop
            return

        # learn src always
        self._learn_mac(src_mac, in_port, zone)

        # -------- ARP handling --------
        if eth.ethertype == 0x0806:
            arp_pkt = pkt.get_protocol(arp.arp)
            if not arp_pkt:
                return
            self._handle_arp(dp, parser, ofp, arp_pkt, in_port, zone, msg.data)
            return

        # -------- IPv4 handling --------
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        tcp_pkt = pkt.get_protocol(tcp.tcp)

        # Firewall logic only cares about TCP->MQTT
        if ip_pkt and tcp_pkt and ip_pkt.dst == MQTT_IP:
            self._handle_tcp_to_mqtt(dp, parser, msg, zone, ip_pkt, tcp_pkt)
            return

        # Otherwise: plain L2 switching but only inside same zone
        self._zone_learning_forward(dp, parser, ofp, in_port, zone, src_mac, dst_mac, msg)

    # ------------------ Zone helpers ------------------
    def _zone_for_in_port(self, in_port: int) -> Optional[str]:
        name = self.port_no_to_name.get(in_port)
        if not name:
            # fallback: assume ofport==ethX index
            name = f"eth{in_port}"
        if name in INT_PORT_NAMES:
            return "INT"
        if name in EXT_PORT_NAMES:
            return "EXT"
        return None

    def _ports_in_zone(self, zone: str) -> Set[int]:
        names = INT_PORT_NAMES if zone == "INT" else EXT_PORT_NAMES
        ports = set()
        for n in names:
            p = self.port_name_to_no.get(n)
            if p is not None:
                ports.add(p)
        return ports

    def _learn_mac(self, mac: str, port_no: int, zone: str):
        self.mac_to_port[mac] = port_no
        self.mac_to_zone[mac] = zone

    # ------------------ ARP ------------------
    def _handle_arp(self, dp, parser, ofp, arp_pkt: arp.arp, in_port: int, zone: str, raw_data: bytes):
        # learn sender
        if arp_pkt.src_ip and arp_pkt.src_mac:
            HOST_MACS[arp_pkt.src_ip] = arp_pkt.src_mac
            self.ip_to_mac[arp_pkt.src_ip] = arp_pkt.src_mac
            HOST_PORTS[arp_pkt.src_ip] = self.port_no_to_name.get(in_port, f"eth{in_port}")
            self.port_name_to_no.setdefault(self.port_no_to_name.get(in_port, f"eth{in_port}"), in_port)

        target_mac = None
        if arp_pkt.dst_ip in self.ip_to_mac:
            target_mac = self.ip_to_mac[arp_pkt.dst_ip]
        elif arp_pkt.dst_ip in self.gateway_ips:
            target_mac = self.gateway_mac

        if arp_pkt.opcode == arp.ARP_REQUEST and target_mac:
            self.logger.info("Proxy ARP %s asks for %s -> %s", arp_pkt.src_ip, arp_pkt.dst_ip, target_mac)
            ether_reply = ethernet.ethernet(dst=arp_pkt.src_mac, src=target_mac, ethertype=0x0806)
            arp_reply = arp.arp(opcode=arp.ARP_REPLY,
                                src_mac=target_mac, src_ip=arp_pkt.dst_ip,
                                dst_mac=arp_pkt.src_mac, dst_ip=arp_pkt.src_ip)
            pkt_out = packet.Packet()
            pkt_out.add_protocol(ether_reply)
            pkt_out.add_protocol(arp_reply)
            pkt_out.serialize()
            actions = [parser.OFPActionOutput(in_port)]
            out = parser.OFPPacketOut(datapath=dp,
                                      buffer_id=ofp.OFP_NO_BUFFER,
                                      in_port=ofp.OFPP_CONTROLLER,
                                      actions=actions,
                                      data=pkt_out.data)
            dp.send_msg(out)
            return

        # Normal ARP: flood only inside same zone (INT or EXT)
        self._flood_zone(dp, parser, ofp, zone, in_port, raw_data)

    # ------------------ L2 forwarding (per-zone learning) ------------------
    def _zone_learning_forward(self, dp, parser, ofp, in_port: int, zone: str, src_mac: str, dst_mac: str, msg):
        # Broadcast / multicast -> flood inside zone
        if dst_mac.startswith("ff:ff:ff:ff:ff:ff") or (int(dst_mac.split(":")[0], 16) & 1):
            self._flood_zone(dp, parser, ofp, zone, in_port, msg.data)
            return

        out_port = self.mac_to_port.get(dst_mac)
        dst_zone = self.mac_to_zone.get(dst_mac)

        # unknown dst -> flood zone
        if not out_port or not dst_zone:
            self._flood_zone(dp, parser, ofp, zone, in_port, msg.data)
            return

        # known but other zone -> drop (default deny between LANs)
        if dst_zone != zone:
            return

        # install reactive flow: in_port + eth_dst -> output (no NORMAL)
        match = parser.OFPMatch(in_port=in_port, eth_dst=dst_mac)
        actions = [parser.OFPActionOutput(out_port)]
        add_flow(dp, 100, match, actions, idle_timeout=60, hard_timeout=0)

        self._packet_out(dp, parser, ofp, in_port, actions, msg)

    def _flood_zone(self, dp, parser, ofp, zone: str, in_port: int, data: bytes):
        ports = sorted(self._ports_in_zone(zone))
        actions = []
        for p in ports:
            if p == in_port:
                continue
            actions.append(parser.OFPActionOutput(p))

        if not actions:
            return

        out = parser.OFPPacketOut(
            datapath=dp,
            buffer_id=ofp.OFP_NO_BUFFER,
            in_port=ofp.OFPP_CONTROLLER,
            actions=actions,
            data=data
        )
        dp.send_msg(out)

    def _packet_out(self, dp, parser, ofp, in_port: int, actions, msg):
        data = None
        if msg.buffer_id == ofp.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(
            datapath=dp,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data
        )
        dp.send_msg(out)

    def _install_static_flows(self):
        dp = self.datapath
        if not dp:
            return
        parser = dp.ofproto_parser
        # L2 forwarding for known hosts (all except mqtt to avoid bypassing policy)
        for name, data in HOSTS.items():
            ip = data["ip"]
            mac = data["mac"]
            if ip == MQTT_IP:
                continue
            port_no = self._port_no_for_ip(ip)
            if not port_no:
                continue
            add_flow(dp, 150, parser.OFPMatch(eth_dst=mac), [parser.OFPActionOutput(port_no)])
        # TCP to MQTT -> controller for inspection/detection (deny by default)
        add_flow(dp, 300, parser.OFPMatch(eth_type=0x0800, ip_proto=6, ipv4_dst=MQTT_IP),
                 [parser.OFPActionOutput(dp.ofproto.OFPP_CONTROLLER, MIRROR_LEN)])

    # ------------------ MQTT firewall path ------------------
    def _handle_tcp_to_mqtt(self, dp, parser, msg, zone: str, ip_pkt: ipv4.ipv4, tcp_pkt: tcp.tcp):
        src_ip = ip_pkt.src
        dst_ip = ip_pkt.dst
        dst_port = tcp_pkt.dst_port

        self.logic.record_packet(src_ip, dst_ip, dst_port, len(msg.data))

        # quick src classification
        try:
            src_addr = ip_address(src_ip)
        except ValueError:
            return

        is_internal_src = src_addr in ALLOWED_INT_SUBNET

        # DoS / portscan detection ONLY when someone targets MQTT (internal or external)
        if self.logic.track_portscan(src_ip, dst_port):
            self.logic.log_event(
                "PORTSCAN_DETECTED",
                src_ip=src_ip,
                dst_ip=dst_ip,
                dst_port=dst_port,
                threshold=self.logic.portscan_threshold
            )
            self._block_ip(dp, src_ip, PORTSCAN_BLOCK_SECONDS, reason="PORTSCAN_DETECTED", target="MQTT")
            return

        if self.logic.track_dos(src_ip):
            self.logic.log_event(
                "DOS_DETECTED",
                src_ip=src_ip,
                dst_ip=dst_ip,
                threshold=self.logic.dos_threshold
            )
            self._block_ip(dp, src_ip, DOS_BLOCK_SECONDS, reason="DOS_DETECTED", target="MQTT")
            return

        # L4 policy:
        # - Only allow TCP 1883/8883 from INTERNAL to MQTT
        # - Deny everything else (and log attempts)
        if dst_port in MQTT_PORTS and is_internal_src and zone == "INT":
            allowed = True
        else:
            allowed = False

        self.logic.record_mqtt_attempt(src_ip, allowed)

        if not allowed:
            self.logic.log_event("MQTT_DENIED", src_ip=src_ip, dst_ip=dst_ip, dst_port=dst_port, zone=zone)
            return

        # allowed -> forward deterministically (no learning-switch ambiguity)
        mqtt_mac = HOSTS["mqtt"]["mac"].lower()
        mqtt_port_no = self._port_no_for_ip(MQTT_IP)
        if not mqtt_port_no:
            # fallback: try learned MAC
            mqtt_port_no = self.mac_to_port.get(mqtt_mac)
        if not mqtt_port_no:
            return

        in_port = msg.match["in_port"]
        src_mac = packet.Packet(msg.data).get_protocol(ethernet.ethernet).src.lower()

        # forward to mqtt host
        match_fwd = parser.OFPMatch(
            in_port=in_port,
            eth_type=0x0800,
            ip_proto=6,
            ipv4_src=src_ip,
            ipv4_dst=MQTT_IP,
            tcp_dst=dst_port,
        )
        actions_fwd = [
            parser.OFPActionSetField(eth_dst=mqtt_mac),
            parser.OFPActionOutput(mqtt_port_no),
        ]
        add_flow(dp, 650, match_fwd, actions_fwd, idle_timeout=60, hard_timeout=0)

        # reverse flow mqtt -> client (same tcp port as src on return)
        # Note: reply uses tcp_src=dst_port
        client_mac = src_mac
        match_rev = parser.OFPMatch(
            in_port=mqtt_port_no,
            eth_type=0x0800,
            ip_proto=6,
            ipv4_src=MQTT_IP,
            ipv4_dst=src_ip,
            tcp_src=dst_port,
        )
        actions_rev = [
            parser.OFPActionSetField(eth_dst=client_mac),
            parser.OFPActionOutput(in_port),
        ]
        add_flow(dp, 650, match_rev, actions_rev, idle_timeout=60, hard_timeout=0)

        # immediate packet out according to forward actions
        self._packet_out(dp, parser, dp.ofproto, in_port, actions_fwd, msg)

    def _port_no_for_ip(self, ip: str) -> Optional[int]:
        port_name = HOST_PORTS.get(ip)
        if not port_name:
            return None
        return self.port_name_to_no.get(port_name)

    # ------------------ Blocking helpers ------------------
    def _block_ip(self, dp, ip: str, seconds: int, reason: str, target: str = "MQTT"):
        expires = self.logic.block_ip(ip, seconds, reason=reason, target=target)
        parser = dp.ofproto_parser
        match = parser.OFPMatch(eth_type=0x0800, ipv4_src=ip)
        add_flow(dp, 800, match, [], hard_timeout=seconds)
        self.logger.warning("Blocking %s for %ss due to %s", ip, seconds, reason)
        return expires

    def _block_port(self, dp, port: int, scope: str, seconds: int, override_allow: bool, reason: str):
        expires = self.logic.block_port(port, scope=scope, seconds=seconds, override_allow=override_allow, reason=reason)
        priority = OVERRIDE_PORT_BLOCK_PRIORITY if override_allow else DEFAULT_PORT_BLOCK_PRIORITY
        targets = MQTT_HOSTS if scope == "mqtt" else [None]
        for target in targets:
            add_drop_flow_for_port(dp, port, scope, mqtt_ip=target, hard_timeout=seconds, priority=priority)
        self.logger.warning(
            "Blocking port %s scope=%s for %ss (override_allow=%s) due to %s",
            port, scope, seconds, override_allow, reason
        )
        return expires

    def _policy_rule_count(self):
        # rough estimate: miss->controller + dynamic deny flows + mqtt allow flows (reactive)
        # keep as an estimate for UI
        base = 1  # miss->controller
        dynamic = len(self.logic.blocked_ips) + len(self.logic.blocked_ports)
        return base + dynamic

    def _estimate_active_rules(self):
        return self._policy_rule_count()
