"""
log_agent.py

Main LogAgent - orchestrates all collectors and ships events to the
central log collector VM.

Usage:
    sudo python3 log_agent.py

The agent:
1. Instantiates all registered collectors
2. Calls on_start() on each to capture baselines
3. Polls each collector every POLL_INTERVAL seconds
4. Batches all events and ships them via LogShipper
5. Handles SIGTERM/SIGINT for graceful shutdown

To add a new attack collector:
1. Create collectors/your_collector.py subclassing BaseCollector
2. Import it here and add to REGISTERED_COLLECTORS
"""

import time
import signal
import sys
import os
import socket
from typing import List
from datetime import datetime

from collectors.base_collector import BaseCollector
from collectors.ebpf_collector import EbpfCollector
from collectors.cron_collector import CronCollector
from collectors.arp_spoof_collector import ArpSpoofCollector
# Future collectors get imported and added here:
# from collectors.tcp_session_collector import TcpSessionCollector

from shipper import LogShipper



# Central server ip and port
COLLECTOR_IP = "10.10.0.10"
COLLECTOR_PORT = 8443

# This VM's IP - auto-detected if left as None
VM_IP = None

# How often to poll collectors and ship logs (seconds)
POLL_INTERVAL = 5

# TLS certificate paths (set to None for lab with self-signed/no-verify)
CA_CERT = None        # Path to CA cert to verify collector
CLIENT_CERT = None    # Path to client cert for mutual TLS


# Add new collector classes here as attacks are implemented
def build_collectors(vm_ip: str) -> List[BaseCollector]:
    """
    Instantiate all active collectors.
    Each collector gets the VM IP and an optional config dict.
    """
    collectors = []

    # eBPF injection detector
    collectors.append(EbpfCollector(
        vm_ip=vm_ip,
        config={
            # Add any process names on this VM that legitimately use eBPF
            "bpf_whitelist": {
                "systemd", "dockerd", "containerd",
                "falco", "cilium", "prometheus",
            }
        }
    ))

    # Cron job abuse detector
    collectors.append(CronCollector(vm_ip=vm_ip))
    collectors.append(ArpSpoofCollector(vm_ip=vm_ip))
    # Future collectors - uncomment as implemented:
    # collectors.append(TcpSessionCollector(vm_ip=vm_ip))

    return collectors


def get_vm_ip() -> str:
    """Auto-detect this VM's primary IP address"""
    try:
        # Connect to an external address to determine outbound IP
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("10.10.0.1", 80))
            return s.getsockname()[0]
    except Exception:
        return "unknown"


class LogAgent:
    """
    Main agent that coordinates collectors and log shipping.
    Runs as a long-lived service on each victim VM.
    """

    def __init__(self):
        self.vm_ip = VM_IP or get_vm_ip()
        self.running = False
        self.collectors: List[BaseCollector] = []
        self.shipper: LogShipper = None

        # Track stats
        self._total_events = 0
        self._poll_count = 0
        self._start_time = None

    def setup(self):
        """Initialize collectors and shipper"""
        print(f"[agent] VM IP: {self.vm_ip}")
        print(f"[agent] Collector: {COLLECTOR_IP}:{COLLECTOR_PORT}")
        print(f"[agent] Poll interval: {POLL_INTERVAL}s")
        print()

        # Build shipper
        self.shipper = LogShipper(
            collector_ip=COLLECTOR_IP,
            collector_port=COLLECTOR_PORT,
            vm_ip=self.vm_ip,
            cafile=CA_CERT,
            certfile=CLIENT_CERT,
        )

        # Build and initialize collectors
        self.collectors = build_collectors(self.vm_ip)

        print(f"[agent] Initializing {len(self.collectors)} collector(s)...")
        for collector in self.collectors:
            print(f"[agent]   - {collector.name}")
            try:
                collector.on_start()
            except Exception as e:
                print(f"[agent] WARNING: {collector.name} on_start() failed: {e}")

        print()

    def run(self):
        """Main poll loop"""
        self.running = True
        self._start_time = datetime.utcnow()

        print(f"[agent] Started at {self._start_time.isoformat()}Z")
        print(f"[agent] Monitoring active. Press Ctrl+C to stop.\n")

        while self.running:
            loop_start = time.time()

            self._poll_and_ship()

            # Sleep for remainder of poll interval
            elapsed = time.time() - loop_start
            sleep_time = max(0, POLL_INTERVAL - elapsed)
            time.sleep(sleep_time)

        self._shutdown()

    def _poll_and_ship(self):
        """Poll all collectors and ship any events found"""
        self._poll_count += 1
        all_events = []

        for collector in self.collectors:
            try:
                events = collector.collect()
                if events:
                    all_events.extend(events)
                    print(
                        f"[agent] [{collector.name}] "
                        f"{len(events)} event(s) collected"
                    )
            except Exception as e:
                print(f"[agent] [{collector.name}] collect() error: {e}")

        if all_events:
            self._total_events += len(all_events)
            shipped = self.shipper.ship(all_events)
            status = "shipped" if shipped else "buffered"
            print(
                f"[agent] {len(all_events)} event(s) {status} "
                f"(total: {self._total_events})"
            )

    def _shutdown(self):
        """Graceful shutdown"""
        print("\n[agent] Shutting down...")

        for collector in self.collectors:
            try:
                collector.on_stop()
            except Exception as e:
                print(f"[agent] [{collector.name}] on_stop() error: {e}")

        if self.shipper:
            self.shipper.close()

        uptime = (datetime.utcnow() - self._start_time).seconds if self._start_time else 0
        print(f"[agent] Uptime: {uptime}s | "
              f"Polls: {self._poll_count} | "
              f"Events: {self._total_events}")
        print("[agent] Stopped.")

    def stop(self):
        """Signal the agent to stop"""
        self.running = False


def main():
    print("=" * 60)
    print("  Cloud Security Lab - Log Collection Agent")
    print("=" * 60)
    print()

    # Must run as root for /proc access and auditd
    if os.geteuid() != 0:
        print("[!] This agent must be run as root (sudo python3 log_agent.py)")
        sys.exit(1)

    agent = LogAgent()

    # Handle graceful shutdown on SIGTERM/SIGINT
    def handle_signal(sig, frame):
        print(f"\n[agent] Received signal {sig}, stopping...")
        agent.stop()

    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    agent.setup()
    agent.run()


if __name__ == "__main__":
    main()
