from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER, set_ev_cls
from ryu.lib import hub
from ryu.lib.packet import packet, ethernet, ipv4, tcp
from ryu.ofproto import ofproto_v1_3
from ryu.app.wsgi import WSGIApplication

from firewall_api import FIREWALL_INSTANCE_NAME, FirewallAPIController
from firewall_logic import FirewallLogic
from of_helpers import add_flow, delete_flows

# Network configuration (match lab startup scripts)
MQTT_HOSTS = ["10.0.10.20"]
ALLOWED_MQTT_SOURCES = ["10.0.10.11"]
MQTT_PORTS = [1883, 8883]

# Detection thresholds
PORTSCAN_THRESHOLD = 6         # unique ports in window
PORTSCAN_WINDOW = 10           # seconds
PORTSCAN_BLOCK_SECONDS = 30

DOS_THRESHOLD = 120            # packets in window
DOS_WINDOW = 5                 # seconds
DOS_BLOCK_SECONDS = 60

DEFAULT_BLOCK_SECONDS = 60


class SDNFirewall(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'wsgi': WSGIApplication}

    def __init__(self, *args, **kwargs):
        super(SDNFirewall, self).__init__(*args, **kwargs)
        wsgi = kwargs['wsgi']

        self.mac_to_port = {}
        self.datapath = None

        self.logic = FirewallLogic(
            mqtt_hosts=MQTT_HOSTS,
            allowed_mqtt_sources=ALLOWED_MQTT_SOURCES,
            mqtt_ports=MQTT_PORTS,
            portscan_threshold=PORTSCAN_THRESHOLD,
            portscan_window=PORTSCAN_WINDOW,
            dos_threshold=DOS_THRESHOLD,
            dos_window=DOS_WINDOW,
            block_seconds=DEFAULT_BLOCK_SECONDS,
            scan_block_seconds=PORTSCAN_BLOCK_SECONDS,
        )

        # Expose REST API
        wsgi.register(FirewallAPIController, {FIREWALL_INSTANCE_NAME: self})

        self.monitor_thread = hub.spawn(self._monitor)

    # ------------------ API helpers ------------------
    def api_status(self):
        status = self.logic.get_status()
        status.update({
            "active_rules": self._estimate_active_rules(),
        })
        return status

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
        return {"removed": True, "ip": ip}

    # ------------------ OpenFlow setup ------------------
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        self.datapath = datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Table-miss: send to controller
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        add_flow(datapath, 0, match, actions)

        # Send ALL TCP traffic destined to MQTT host to controller (for detection)
        for mqtt_ip in MQTT_HOSTS:
            match_tcp_to_mqtt = parser.OFPMatch(
                eth_type=0x0800,
                ip_proto=6,
                ipv4_dst=mqtt_ip
            )
            actions_to_ctrl = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
            add_flow(datapath, 300, match_tcp_to_mqtt, actions_to_ctrl)


        # Block TCP dst port 2020 everywhere (demo)
        match_block_demo = parser.OFPMatch(eth_type=0x0800, ip_proto=6, tcp_dst=2020)
        add_flow(datapath, 400, match_block_demo, [])

        # --- STATIC MQTT POLICY (highest priority) ---
        for mqtt_ip in MQTT_HOSTS:
            for p in MQTT_PORTS:
                # allow from authorized client
                match_allow = parser.OFPMatch(
                    eth_type=0x0800, ip_proto=6,
                    ipv4_src=ALLOWED_MQTT_SOURCES[0],
                    ipv4_dst=mqtt_ip,
                    tcp_dst=p
                )
                actions_allow = [parser.OFPActionOutput(ofproto.OFPP_NORMAL)]
                add_flow(datapath, 500, match_allow, actions_allow)

        self.logger.info("Switch %s configured with base policies + MQTT allow/deny", datapath.id)



    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.datapath = datapath
        elif ev.state == DEAD_DISPATCHER and self.datapath and datapath.id == self.datapath.id:
            self.datapath = None

    # ------------------ Monitor / cleanup ------------------
    def _monitor(self):
        while True:
            hub.sleep(5)
            dp = self.datapath
            if not dp:
                continue

            # Cleanup expired blocks and remove flows
            expired_ips = self.logic.cleanup_expired_blocks()
            for ip in expired_ips:
                match = dp.ofproto_parser.OFPMatch(eth_type=0x0800, ipv4_src=ip)
                delete_flows(dp, match)
                self.logic.log_event("UNBLOCK_IP", ip=ip, reason="timeout")

            # Poll flow stats for MQTT traffic
            req = dp.ofproto_parser.OFPFlowStatsRequest(dp)
            dp.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        body = ev.msg.body
        self.logic.update_flow_counters(body)

    # ------------------ Packet processing ------------------
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth.ethertype == 0x88cc:  # Ignore LLDP
            return

        dst = eth.dst
        src = eth.src
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        tcp_pkt = pkt.get_protocol(tcp.tcp)

        if ip_pkt and tcp_pkt:
            handled = self._handle_tcp(datapath, parser, msg, ip_pkt, tcp_pkt, in_port)
            if handled:
                return

        # Learning switch forwarding
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            add_flow(datapath, 1, match, actions, buffer_id=msg.buffer_id, idle_timeout=120, hard_timeout=0)
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                return

        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=msg.buffer_id,
                                  in_port=in_port,
                                  actions=actions,
                                  data=None if msg.buffer_id != ofproto.OFP_NO_BUFFER else msg.data)
        datapath.send_msg(out)

    def _handle_tcp(self, datapath, parser, msg, ip_pkt, tcp_pkt, in_port):
        src_ip = ip_pkt.src
        dst_ip = ip_pkt.dst
        dst_port = tcp_pkt.dst_port
        self.logger.info("TCP seen src=%s dst=%s dport=%s", src_ip, dst_ip, dst_port)

        # Stats for MQTT traffic
        self.logic.record_packet(src_ip, dst_ip, dst_port, len(msg.data))

        # Port-scan detection against MQTT host (any port)
        if dst_ip in self.logic.mqtt_hosts:
            if self.logic.track_portscan(src_ip, dst_port):
                self.logic.log_event("PORTSCAN_DETECTED", src_ip=src_ip, dst_ip=dst_ip, dst_port=dst_port,
                                     threshold=self.logic.portscan_threshold)
                self._block_ip(datapath, src_ip, PORTSCAN_BLOCK_SECONDS, reason="PORTSCAN_DETECTED", target="MQTT")
                return True

            if self.logic.track_dos(src_ip):
                self.logic.log_event("DOS_DETECTED", src_ip=src_ip, dst_ip=dst_ip,
                                     threshold=self.logic.dos_threshold)
                self._block_ip(datapath, src_ip, DOS_BLOCK_SECONDS, reason="DOS_DETECTED", target="MQTT")
                return True

            if dst_port in self.logic.mqtt_ports:
                if not self.logic.should_allow_mqtt(src_ip, dst_ip):
                    self.logic.log_event("MQTT_DENIED", src_ip=src_ip, dst_ip=dst_ip, dst_port=dst_port)
                    return True
                else:
                    actions = [parser.OFPActionOutput(datapath.ofproto.OFPP_NORMAL)]
                    match = parser.OFPMatch(eth_type=0x0800,
                                            ip_proto=6,
                                            ipv4_src=src_ip,
                                            ipv4_dst=dst_ip,
                                            tcp_dst=dst_port)
                    add_flow(datapath, 275, match, actions, idle_timeout=300, hard_timeout=0, buffer_id=msg.buffer_id)
                    if msg.buffer_id != datapath.ofproto.OFP_NO_BUFFER:
                        return True
                    # allow to continue to L2 forwarding for this packet
        return False

    # ------------------ Blocking helpers ------------------
    def _block_ip(self, datapath, ip: str, seconds: int, reason: str, target: str = "MQTT"):
        expires = self.logic.block_ip(ip, seconds, reason=reason, target=target)
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(eth_type=0x0800, ipv4_src=ip)
        add_flow(datapath, 350, match, [], hard_timeout=seconds)
        self.logger.warning("Blocking %s for %ss due to %s", ip, seconds, reason)
        return expires

    def _estimate_active_rules(self):
        # Base rules: table-miss + demo block + dynamic blocks
        base = 2
        dynamic = len(self.logic.blocked_ips)
        return base + dynamic
