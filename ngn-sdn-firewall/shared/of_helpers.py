import time
from typing import List, Optional


def add_flow(datapath,
             priority: int,
             match,
             actions: List,
             idle_timeout: int = 0,
             hard_timeout: int = 0,
             buffer_id: Optional[int] = None):
    """Install a flow entry with the given parameters."""
    ofproto = datapath.ofproto
    parser = datapath.ofproto_parser

    inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

    if buffer_id is not None and buffer_id != ofproto.OFP_NO_BUFFER:
        mod = parser.OFPFlowMod(datapath=datapath,
                                buffer_id=buffer_id,
                                priority=priority,
                                match=match,
                                idle_timeout=idle_timeout,
                                hard_timeout=hard_timeout,
                                instructions=inst)
    else:
        mod = parser.OFPFlowMod(datapath=datapath,
                                priority=priority,
                                match=match,
                                idle_timeout=idle_timeout,
                                hard_timeout=hard_timeout,
                                instructions=inst)
    datapath.send_msg(mod)


def delete_flows(datapath, match):
    """Remove flows that match the given fields."""
    parser = datapath.ofproto_parser
    ofproto = datapath.ofproto
    mod = parser.OFPFlowMod(datapath=datapath,
                            command=ofproto.OFPFC_DELETE,
                            out_port=ofproto.OFPP_ANY,
                            out_group=ofproto.OFPG_ANY,
                            match=match)
    datapath.send_msg(mod)


def now() -> float:
    return time.time()


def _match_for_port(parser, port: int, scope: str, mqtt_ip: str = None):
    """Build a match object for a TCP dst port with optional MQTT scope."""
    if scope == "mqtt" and mqtt_ip:
        return parser.OFPMatch(eth_type=0x0800, ip_proto=6, ipv4_dst=mqtt_ip, tcp_dst=port)
    return parser.OFPMatch(eth_type=0x0800, ip_proto=6, tcp_dst=port)


def add_drop_flow_for_port(datapath,
                           port: int,
                           scope: str,
                           mqtt_ip: str = None,
                           hard_timeout: int = 0,
                           priority: int = 480):
    """Install a drop flow for the given TCP destination port."""
    parser = datapath.ofproto_parser
    match = _match_for_port(parser, port, scope, mqtt_ip)
    add_flow(datapath, priority, match, [], hard_timeout=hard_timeout)


def delete_drop_flow_for_port(datapath, port: int, scope: str, mqtt_ip: str = None):
    """Remove drop flows for a TCP destination port."""
    parser = datapath.ofproto_parser
    match = _match_for_port(parser, port, scope, mqtt_ip)
    delete_flows(datapath, match)
