from collectors.base_collector import BaseCollector
from typing import List, Dict, Any
from scapy.all import sniff, ARP, conf
import threading


class ArpSpoofCollector(BaseCollector):

    def __init__(self, vm_ip: str):
        super().__init__(vm_ip=vm_ip)

        # Stores the VM IP
        self.vm_ip = vm_ip

        # Auto detects the gateway
        self.gateway_ip = conf.route.route("0.0.0.0")[2]

        self.known_gateway_mac = None
        self.events = []
        self.lock = threading.Lock()

        # ARP state table
        self.arp_table = {}

        # Interface selection
        self.interface = conf.iface

    @property
    def name(self) -> str:
        return "arp_spoofing"

    def on_start(self):
        thread = threading.Thread(target=self.start_sniffing, daemon=True)
        thread.start()

    def start_sniffing(self):
        sniff(
            filter="arp",
            iface=self.interface,
            prn=self.process_packet,
            store=False
        )

    def process_packet(self, packet):
        if packet.haslayer(ARP):
            ip = packet[ARP].psrc
            mac = packet[ARP].hwsrc

            with self.lock:

                # Learns the baseline gateway MAC address
                if ip == self.gateway_ip and self.known_gateway_mac is None:
                    self.known_gateway_mac = mac
                    return

                # Detects when the Gateway MAC address is changed   
                if ip == self.gateway_ip and self.known_gateway_mac and mac != self.known_gateway_mac:
                    self.create_event(ip, mac, "Gateway MAC address changed")

                # Detects when the same MAC address is used across multiple IPs
                for stored_ip, stored_mac in self.arp_table.items():
                    if stored_mac == mac and stored_ip != ip:
                        self.create_event(ip, mac, "Same MAC address detected across multiple IPs")

                # Update table
                self.arp_table[ip] = mac

    def create_event(self, ip, mac, reason):

        event = self.build_event(
            severity="critical",
            description=f"ARP Spoofing Detected: {reason}",
            alert_type=self.name,

            attacker_ip=ip,
            attacker_mac=mac,
            gateway_ip=self.gateway_ip,
            real_gateway_mac=self.known_gateway_mac,

            source_vm=self.vm_ip,
            detection_method="arp_table_analysis"
        )

        self.events.append(event)

    def collect(self) -> List[Dict[str, Any]]:
        with self.lock:
            events = self.events.copy()
            self.events.clear()
        return events