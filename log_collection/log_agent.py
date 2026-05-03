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
from collectors.tcp_session_collector import TcpSessionCollector

from shipper import LogShipper



# Definitions
COLLECTOR_IP = "10.10.0.10"
COLLECTOR_PORT = 8443
VM_IP = None
POLL_INTERVAL = 5
CA_CERT = None
CLIENT_CERT = None


# adds collector classes here
def build_collectors(vm_ip: str) -> List[BaseCollector]:
    """
    Each collector gets the VM IP and an optional config dict ebpf needs it to reduce false positives
    """
    collectors = []

    # collectors added to collectors list
    collectors.append(EbpfCollector(
        vm_ip=vm_ip,
        config={
            "bpf_whitelist": {
                "systemd", "dockerd", "containerd",
                "falco", "cilium", "prometheus", "bpftool",
            }
        }
    ))
    collectors.append(CronCollector(vm_ip=vm_ip))
    collectors.append(ArpSpoofCollector(vm_ip=vm_ip))
    collectors.append(TcpSessionCollector(vm_ip=vm_ip))

    return collectors


def get_vm_ip() -> str:
    # grabs current vms ip
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("10.10.0.1", 80))
            return s.getsockname()[0]
    except Exception:
        return "unknown"


class LogAgent:
    """
    Main agent that coordinates collectors and log shipping.
    """
    # defines logging vars
    def __init__(self):
        self.vm_ip = VM_IP or get_vm_ip()
        self.running = False
        self.collectors: List[BaseCollector] = []
        self.shipper: LogShipper = None

        # Track stats
        self._total_events = 0
        self._poll_count = 0
        self._start_time = None
    

    # initializes collector and shipper
    def setup(self):
        print(f"[agent] VM IP: {self.vm_ip}")
        print(f"[agent] Collector: {COLLECTOR_IP}:{COLLECTOR_PORT}")
        print(f"[agent] Poll interval: {POLL_INTERVAL}s")
        print()

        # Build shipper and collectors
        self.shipper = LogShipper(
            collector_ip=COLLECTOR_IP,
            collector_port=COLLECTOR_PORT,
            vm_ip=self.vm_ip,
            cafile=CA_CERT,
            certfile=CLIENT_CERT,
        )
        self.collectors = build_collectors(self.vm_ip)
        print(f"[agent] Initializing {len(self.collectors)} collector(s)...")
        for collector in self.collectors:
            print(f"[agent]   - {collector.name}")
            try:
                collector.on_start()
            except Exception as e:
                print(f"[agent] WARNING: {collector.name} on_start() failed: {e}")

        print()


    # time monitoring
    def run(self):
        self.running = True
        self._start_time = datetime.utcnow()

        print(f"[agent] Started at {self._start_time.isoformat()}Z")
        print(f"[agent] Monitoring active. Press Ctrl+C to stop.\n")

        while self.running:
            loop_start = time.time()

            self._poll_and_ship()

            # sleeps for remainder of poll interval
            elapsed = time.time() - loop_start
            sleep_time = max(0, POLL_INTERVAL - elapsed)
            time.sleep(sleep_time)

        self._shutdown()


    # grabs collector events and ships it
    def _poll_and_ship(self):
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


    # shutdown handling
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

    # must run as root for /proc access and auditd
    if os.geteuid() != 0:
        print("[!] This agent must be run as root (sudo python3 log_agent.py)")
        sys.exit(1)

    agent = LogAgent()

    # stop handling
    def handle_signal(sig, frame):
        print(f"\n[agent] Received signal {sig}, stopping...")
        agent.stop()

    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    agent.setup()
    agent.run()


if __name__ == "__main__":
    main()
