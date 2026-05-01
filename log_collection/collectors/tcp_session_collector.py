from typing import List, Dict, Any
from scapy.all import sniff, TCP, IP
import threading
from collectors.base_collector import BaseCollector


class TcpSessionCollector(BaseCollector):

    def __init__(self, vm_ip: str, config: Dict[str, Any] = None):
        super().__init__(vm_ip, config)
        self._events = []  # store events until agent polls them

    @property
    def name(self) -> str:
        return "tcp_session"  # must match handler alert_type

    def collect(self) -> List[Dict[str, Any]]:
        events = self._events[:]   # copy events
        self._events.clear()       # clear after sending
        return events

    def on_start(self):
        t = threading.Thread(
            target=sniff,
            kwargs={
                "iface": self.config.get("interface"),
                "filter": "tcp",
                "prn": self._process_packet,
                "store": 0,
            },
            daemon=True
        )
        t.start()

    def _process_packet(self, packet):
        # ignore packets without TCP/IP layers
        if not packet.haslayer(TCP) or not packet.haslayer(IP):
            return

        tcp = packet[TCP]
        ip = packet[IP]

        # check for RST flag (connection reset)
        if tcp.flags == 0x04:
            event = self.build_event(
                severity="high",
                description=f"TCP RST detected from {ip.src}",
                event_type="rst",
                src_ip=ip.src,
                dst_ip=ip.dst,
                src_port=tcp.sport,
                dst_port=tcp.dport
            )
            self._events.append(event)  # store event

    def log_session_event(self, session_id: str, src_ip: str):
        event = self.build_event(
            severity="high",
            description=f"Session activity from {src_ip}",
            event_type="session",
            session_id=session_id,
            src_ip=src_ip
        )
        self._events.append(event)