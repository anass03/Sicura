import threading
from collections import defaultdict, deque
from typing import Deque, Dict, List, Optional, Tuple

from of_helpers import now


class FirewallLogic:
    def __init__(
        self,
        mqtt_hosts: List[str],
        allowed_mqtt_sources: List[str],
        mqtt_ports: Optional[List[int]] = None,
        allowed_subnet: Optional[str] = None,
        portscan_threshold: int = 6,
        portscan_window: int = 10,
        dos_threshold: int = 120,
        dos_window: int = 5,
        block_seconds: int = 60,
        scan_block_seconds: int = 30,
    ):
        self.mqtt_hosts = set(mqtt_hosts)
        self.allowed_mqtt_sources = set(allowed_mqtt_sources)
        self.mqtt_ports = set(mqtt_ports or [1883, 8883])
        self.allowed_subnet = allowed_subnet

        self.portscan_threshold = portscan_threshold
        self.portscan_window = portscan_window
        self.scan_block_seconds = scan_block_seconds

        self.dos_threshold = dos_threshold
        self.dos_window = dos_window
        self.block_seconds = block_seconds

        self.lock = threading.Lock()
        self.events: Deque[Dict] = deque(maxlen=500)
        self.event_counters: Dict[str, int] = defaultdict(int)

        self.blocked_ips: Dict[str, Dict] = {}
        self.blocked_ports: Dict[Tuple[str, int, bool], Dict] = {}

        self.mqtt_attempts: Dict[str, Dict[str, int]] = defaultdict(lambda: {"allowed": 0, "denied": 0})

        # Stats from flows
        self.traffic_to_mqtt = {"packets": 0, "bytes": 0}
        self.top_talkers: List[Dict] = []
        self.packet_talkers: Dict[str, Dict[str, int]] = defaultdict(lambda: {"packets": 0, "bytes": 0})

        # Detection caches
        self._scan_history: Dict[str, Deque] = defaultdict(deque)
        self._dos_history: Dict[str, Deque] = defaultdict(deque)

    def log_event(self, event_type: str, **details):
        event = {"type": event_type, "timestamp": now(), **details}
        with self.lock:
            self.events.appendleft(event)
            self.event_counters[event_type] += 1
        return event

    def get_recent_events(self, limit: int = 200):
        with self.lock:
            return list(list(self.events)[:limit])

    def record_packet(self, src_ip: str, dst_ip: str, dst_port: int, byte_len: int):
        if dst_ip not in self.mqtt_hosts:
            return
        with self.lock:
            self.traffic_to_mqtt["packets"] += 1
            self.traffic_to_mqtt["bytes"] += byte_len
            self.packet_talkers[src_ip]["packets"] += 1
            self.packet_talkers[src_ip]["bytes"] += byte_len

    def record_mqtt_attempt(self, src_ip: str, allowed: bool):
        key = "allowed" if allowed else "denied"
        with self.lock:
            self.mqtt_attempts[src_ip][key] += 1

    def track_portscan(self, src_ip: str, dst_port: int) -> bool:
        now_ts = now()
        history = self._scan_history[src_ip]
        history.append((now_ts, dst_port))
        while history and now_ts - history[0][0] > self.portscan_window:
            history.popleft()
        unique_ports = {p for _, p in history}
        return len(unique_ports) >= self.portscan_threshold

    def track_dos(self, src_ip: str) -> bool:
        now_ts = now()
        history = self._dos_history[src_ip]
        history.append(now_ts)
        while history and now_ts - history[0] > self.dos_window:
            history.popleft()
        return len(history) >= self.dos_threshold

    def block_ip(self, ip: str, seconds: Optional[int], reason: str, target: str = "MQTT"):
        expires_at = now() + (seconds if seconds else self.block_seconds)
        with self.lock:
            self.blocked_ips[ip] = {"expires_at": expires_at, "reason": reason, "target": target}
        self.log_event("BLOCK_IP", ip=ip, duration=seconds or self.block_seconds, reason=reason, target=target)
        return expires_at

    def unblock_ip(self, ip: str, reason: str = "manual"):
        removed = False
        with self.lock:
            if ip in self.blocked_ips:
                removed = True
                self.blocked_ips.pop(ip, None)
        if removed:
            self.log_event("UNBLOCK_IP", ip=ip, reason=reason)
        return removed

    def cleanup_expired_blocks(self):
        now_ts = now()
        expired = []
        with self.lock:
            for ip, data in list(self.blocked_ips.items()):
                if now_ts >= data.get("expires_at", 0):
                    expired.append(ip)
                    self.blocked_ips.pop(ip, None)
        return expired

    def block_port(self, port: int, scope: str = "mqtt", seconds: Optional[int] = None, override_allow: bool = False, reason: str = "manual"):
        expires_at = now() + (seconds if seconds else self.block_seconds)
        key = (scope, int(port), bool(override_allow))
        entry = {"port": int(port), "scope": scope, "override_allow": bool(override_allow), "expires_at": expires_at}
        with self.lock:
            self.blocked_ports[key] = entry
        self.log_event("PORT_BLOCKED", port=int(port), scope=scope, seconds=seconds or self.block_seconds, override_allow=bool(override_allow), reason=reason)
        return expires_at

    def unblock_port(self, port: int, scope: str = "mqtt", override_allow: Optional[bool] = None, reason: str = "manual"):
        removed = []
        with self.lock:
            for key in list(self.blocked_ports.keys()):
                k_scope, k_port, k_override = key
                if k_port == int(port) and k_scope == scope and (override_allow is None or k_override == bool(override_allow)):
                    removed.append(self.blocked_ports.pop(key))
        for entry in removed:
            self.log_event("PORT_UNBLOCKED", port=entry["port"], scope=entry["scope"], override_allow=entry["override_allow"], reason=reason)
        return removed

    def cleanup_expired_port_blocks(self):
        now_ts = now()
        expired = []
        with self.lock:
            for key, data in list(self.blocked_ports.items()):
                if now_ts >= data.get("expires_at", 0):
                    expired.append(self.blocked_ports.pop(key))
        return expired

    def update_flow_counters(self, flow_stats):
        total_packets = 0
        total_bytes = 0
        per_src: Dict[str, Dict[str, int]] = defaultdict(lambda: {"packets": 0, "bytes": 0})

        for stat in flow_stats:
            fields = dict(stat.match.items())
            dst_ip = fields.get("ipv4_dst")
            if dst_ip not in self.mqtt_hosts:
                continue
            total_packets += stat.packet_count
            total_bytes += stat.byte_count
            src_ip = fields.get("ipv4_src")
            if not src_ip:
                continue
            per_src[src_ip]["packets"] += stat.packet_count
            per_src[src_ip]["bytes"] += stat.byte_count

        with self.lock:
            self.traffic_to_mqtt = {"packets": total_packets, "bytes": total_bytes}
            merged = defaultdict(lambda: {"packets": 0, "bytes": 0})
            for ip, data in per_src.items():
                merged[ip]["packets"] += data["packets"]
                merged[ip]["bytes"] += data["bytes"]
            for ip, data in self.packet_talkers.items():
                merged[ip]["packets"] += data["packets"]
                merged[ip]["bytes"] += data["bytes"]

            self.top_talkers = sorted(
                [{"ip": ip, "packets": d["packets"], "bytes": d["bytes"]} for ip, d in merged.items()],
                key=lambda x: (x["bytes"], x["packets"]),
                reverse=True,
            )

    def get_status(self):
        with self.lock:
            return {
                "mqtt_hosts": list(self.mqtt_hosts),
                "allowed_mqtt_sources": list(self.allowed_mqtt_sources),
                "allowed_mqtt_subnet": self.allowed_subnet,
                "mqtt_ports": list(self.mqtt_ports),
                "event_counters": dict(self.event_counters),
                "blocked_ips": self.blocked_ips.copy(),
                "blocked_ports": list(self.blocked_ports.values()),
                "traffic_to_mqtt": dict(self.traffic_to_mqtt),
                "top_talkers": list(self.top_talkers),
                "mqtt_attempts": {ip: dict(data) for ip, data in self.mqtt_attempts.items()},
            }

