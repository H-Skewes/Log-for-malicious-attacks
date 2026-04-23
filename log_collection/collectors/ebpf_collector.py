"""
collectors/ebpf_collector.py

Log collector for eBPF program injection attacks.

Monitors:
1. bpf() syscall invocations via auditd - flags non-whitelisted callers
2. Outbound connections via /proc/net/tcp - flags unknown processes
   connecting to internal IPs on suspicious ports
3. Loaded eBPF programs via bpftool - flags unexpected programs

Integrates with the BaseCollector interface so LogAgent can
run it alongside other attack collectors transparently.
"""

import subprocess
import json
import os
import re
import socket
import struct
from typing import List, Dict, Any, Set
from datetime import datetime

from collectors.base_collector import BaseCollector


# Processes legitimately allowed to call bpf()
# Expand this whitelist to match your environment
DEFAULT_BPF_WHITELIST = {
    "systemd",
    "dockerd",
    "containerd",
    "falco",
    "cilium",
    "prometheus",
    "node_exporter",
}

# Ports that suggest exfiltration when seen on outbound connections
# from unexpected processes
SUSPICIOUS_PORTS = {4444, 9001, 1337, 31337, 4545, 5555}

# Internal subnet prefix - connections to these from unknown processes are flagged
INTERNAL_SUBNET = "10.10.0."


class EbpfCollector(BaseCollector):
    """
    Detects eBPF program injection attacks by monitoring:
    - auditd bpf() syscall events
    - /proc/net/tcp for suspicious outbound connections
    - bpftool prog list for unexpected loaded programs
    """

    def __init__(self, vm_ip: str, config: Dict[str, Any] = None):
        super().__init__(vm_ip, config)

        # Whitelist of process names allowed to call bpf()
        self.bpf_whitelist: Set[str] = set(
            self.config.get("bpf_whitelist", DEFAULT_BPF_WHITELIST)
        )

        # Track audit log position to avoid re-reporting old events
        self._last_audit_timestamp = None

        # Baseline of known eBPF program IDs at startup
        self._baseline_bpf_programs: Set[int] = set()

        # Known good outbound connections (pid -> dest) seen at baseline
        self._baseline_connections: Set[str] = set()

    @property
    def name(self) -> str:
        return "ebpf_injection"

    def on_start(self):
        """Capture baseline state when agent starts"""
        self._baseline_bpf_programs = self._get_loaded_bpf_program_ids()
        self._baseline_connections = self._get_current_connections()
        self._last_audit_timestamp = datetime.utcnow()
        print(f"[{self.name}] Baseline: {len(self._baseline_bpf_programs)} eBPF programs, "
              f"{len(self._baseline_connections)} connections")

    def collect(self) -> List[Dict[str, Any]]:
        """
        Run all three detection checks and return any events found.
        Called every N seconds by LogAgent.
        """
        events = []

        events.extend(self._check_bpf_syscalls())
        events.extend(self._check_outbound_connections())
        events.extend(self._check_loaded_programs())

        return events

    # Detection Check 1 auditd bpf() syscall monitoring
    def _check_bpf_syscalls(self) -> List[Dict[str, Any]]:
        """
        Parse auditd logs for bpf() syscall invocations.
        Flags any call from a process not in the whitelist.
        """
        events = []

        try:
            # Use ausearch to get recent bpf() syscall audit events
            result = subprocess.run(
                ["ausearch", "-sc", "bpf", "--start", "recent", "-i"],
                capture_output=True,
                text=True,
                timeout=5
            )

            if result.returncode != 0 and not result.stdout:
                return events

            # Parse each audit record
            current_record = {}
            for line in result.stdout.split('\n'):
                line = line.strip()
                if not line:
                    # End of a record - process it
                    if current_record:
                        event = self._process_audit_record(current_record)
                        if event:
                            events.append(event)
                        current_record = {}
                    continue

                # Parse key=value pairs from audit line
                # Format: type=SYSCALL msg=audit(...) arch=... syscall=... comm="..." exe="..."
                pairs = re.findall(r'(\w+)=(?:"([^"]*)"|([\S]*))', line)
                for key, quoted_val, unquoted_val in pairs:
                    current_record[key] = quoted_val if quoted_val else unquoted_val

        except subprocess.TimeoutExpired:
            pass
        except FileNotFoundError:
            # ausearch not available - auditd may not be installed
            pass
        except Exception as e:
            print(f"[{self.name}] auditd check error: {e}")

        return events

    def _process_audit_record(self, record: Dict[str, str]) -> Dict[str, Any]:
        """
        Process a parsed auditd record and return an event if suspicious.
        """
        comm = record.get("comm", "unknown")
        exe = record.get("exe", "unknown")
        pid = record.get("pid", "unknown")
        uid = record.get("uid", "unknown")
        auid = record.get("auid", "unknown")

        # Clean up comm name (sometimes quoted)
        comm_clean = comm.strip('"').split('/')[-1]

        # Check if this process is whitelisted
        if comm_clean in self.bpf_whitelist:
            return None

        # Also check exe path basename
        exe_basename = exe.strip('"').split('/')[-1]
        if exe_basename in self.bpf_whitelist:
            return None

        return self.build_event(
            severity="critical",
            description=(
                f"Anomalous bpf() syscall from non-whitelisted process: "
                f"comm={comm_clean} exe={exe} pid={pid} uid={uid}"
            ),
            pid=pid,
            uid=uid,
            auid=auid,
            comm=comm_clean,
            exe=exe,
            detection_method="auditd_bpf_syscall",
        )


    # Detection Check 2 /proc/net/tcp outbound connection monitoring
    def _check_outbound_connections(self) -> List[Dict[str, Any]]:
        """
        Read /proc/net/tcp to find outbound connections.
        Flags connections to internal IPs or suspicious ports from
        processes not seen at baseline.
        """
        events = []

        try:
            current = self._get_current_connections()
            new_connections = current - self._baseline_connections

            for conn_key in new_connections:
                parts = conn_key.split("|")
                if len(parts) != 3:
                    continue

                dest_ip, dest_port_str, proc_name = parts
                dest_port = int(dest_port_str)

                is_suspicious = False
                reason = ""

                # Flag connections to internal subnet from unexpected processes
                if dest_ip.startswith(INTERNAL_SUBNET):
                    is_suspicious = True
                    reason = f"unexpected internal connection to {dest_ip}:{dest_port}"

                # Flag connections on known exfiltration ports
                if dest_port in SUSPICIOUS_PORTS:
                    is_suspicious = True
                    reason = f"connection on suspicious port {dest_port} to {dest_ip}"

                if is_suspicious:
                    events.append(self.build_event(
                        severity="high",
                        description=(
                            f"Suspicious outbound connection: {reason} "
                            f"from process {proc_name}"
                        ),
                        dest_ip=dest_ip,
                        dest_port=dest_port,
                        process=proc_name,
                        detection_method="proc_net_tcp",
                    ))

        except Exception as e:
            print(f"[{self.name}] connection check error: {e}")

        return events

    def _get_current_connections(self) -> Set[str]:
        """
        Read /proc/net/tcp and return set of connection keys.
        Key format: "dest_ip|dest_port|process_name"
        """
        connections = set()

        try:
            with open("/proc/net/tcp", "r") as f:
                lines = f.readlines()[1:]  # skip header

            for line in lines:
                parts = line.split()
                if len(parts) < 10:
                    continue

                # Only look at ESTABLISHED connections (state=01)
                state = parts[3]
                if state != "01":
                    continue

                # Destination is parts[2] in hex: XXXXXXXX:PPPP
                remote_hex = parts[2]
                dest_ip = self._hex_to_ip(remote_hex[:8])
                dest_port = int(remote_hex[9:], 16)

                # Get process name from inode
                inode = parts[9]
                proc_name = self._inode_to_process(inode)

                key = f"{dest_ip}|{dest_port}|{proc_name}"
                connections.add(key)

        except Exception:
            pass

        return connections

    def _hex_to_ip(self, hex_ip: str) -> str:
        """Convert little-endian hex IP to dotted decimal"""
        try:
            packed = bytes.fromhex(hex_ip)
            return socket.inet_ntoa(packed[::-1])
        except Exception:
            return "0.0.0.0"

    def _inode_to_process(self, inode: str) -> str:
        """
        Look up which process owns a socket by its inode number.
        Walks /proc/<pid>/fd/ looking for the socket inode.
        """
        try:
            for pid in os.listdir("/proc"):
                if not pid.isdigit():
                    continue
                fd_dir = f"/proc/{pid}/fd"
                try:
                    for fd in os.listdir(fd_dir):
                        link = os.readlink(f"{fd_dir}/{fd}")
                        if f"socket:[{inode}]" in link:
                            with open(f"/proc/{pid}/comm") as f:
                                return f.read().strip()
                except (PermissionError, FileNotFoundError, OSError):
                    continue
        except Exception:
            pass
        return "unknown"

    # Detection Check 3 bpftool loaded program monitoring
    def _check_loaded_programs(self) -> List[Dict[str, Any]]:
        """
        Use bpftool to list currently loaded eBPF programs.
        Flags any program IDs not in the baseline.
        """
        events = []

        try:
            current_ids = self._get_loaded_bpf_program_ids()
            new_ids = current_ids - self._baseline_bpf_programs

            if new_ids:
                # Get details on the new programs
                for prog_id in new_ids:
                    details = self._get_bpf_program_details(prog_id)
                    events.append(self.build_event(
                        severity="critical",
                        description=(
                            f"New eBPF program loaded into kernel: "
                            f"id={prog_id} type={details.get('type', 'unknown')} "
                            f"name={details.get('name', 'unknown')}"
                        ),
                        prog_id=prog_id,
                        prog_type=details.get("type", "unknown"),
                        prog_name=details.get("name", "unknown"),
                        detection_method="bpftool_prog_list",
                    ))

        except FileNotFoundError:
            # bpftool not installed
            pass
        except Exception as e:
            print(f"[{self.name}] bpftool check error: {e}")

        return events

    def _get_loaded_bpf_program_ids(self) -> Set[int]:
        """Get set of currently loaded eBPF program IDs"""
        try:
            result = subprocess.run(
                ["bpftool", "prog", "list", "--json"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0 and result.stdout:
                programs = json.loads(result.stdout)
                return {p["id"] for p in programs if "id" in p}
        except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError):
            pass
        return set()

    def _get_bpf_program_details(self, prog_id: int) -> Dict[str, str]:
        """Get details for a specific eBPF program by ID"""
        try:
            result = subprocess.run(
                ["bpftool", "prog", "show", "id", str(prog_id), "--json"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0 and result.stdout:
                return json.loads(result.stdout)
        except Exception:
            pass
        return {}
