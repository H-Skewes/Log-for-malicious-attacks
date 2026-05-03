import subprocess
import json
import os
import re
import socket
import struct
from typing import List, Dict, Any, Set
from datetime import datetime

from collectors.base_collector import BaseCollector


# doubled white list to make sure nothing slips past log agent
DEFAULT_BPF_WHITELIST = {
    "systemd",
    "dockerd",
    "containerd",
    "falco",
    "cilium",
    "prometheus",
    "node_exporter",
    "bpftool",
}

# irregular ports to build mitigation case
SUSPICIOUS_PORTS = {4444, 9001, 1337, 31337, 4545, 5555}

# internal ips to limit outbound connection flagging
INTERNAL_SUBNET = "10.10.0."
COLLECTOR_IP = "10.10.0.10"


# monitors using auditd bpf syscall events, /proc/net/tcp outbound connection, and bpf prog list for unexpected programs
class EbpfCollector(BaseCollector):
    def __init__(self, vm_ip: str, config: Dict[str, Any] = None):
        super().__init__(vm_ip, config)

        # sets whitelist
        self.bpf_whitelist: Set[str] = set(
            self.config.get("bpf_whitelist", DEFAULT_BPF_WHITELIST)
        )
        # sets time stamps and monitoring baseline
        self._last_audit_timestamp = None
        self._baseline_bpf_programs: Set[int] = set()
        self._baseline_connections: Set[str] = set()


    @property
    def name(self) -> str:
        return "ebpf_injection"


    # sets baseline on start
    def on_start(self):
        self._baseline_bpf_programs = self._get_loaded_bpf_program_ids()
        self._baseline_connections = self._get_current_connections()
        self._last_audit_timestamp = datetime.utcnow()
        print(f"[{self.name}] Baseline: {len(self._baseline_bpf_programs)} eBPF programs, "
              f"{len(self._baseline_connections)} connections")

    # runs detection checks
    def collect(self) -> List[Dict[str, Any]]:
        events = []

        events.extend(self._check_bpf_syscalls())
        events.extend(self._check_outbound_connections())
        events.extend(self._check_loaded_programs())

        return events

    # audit bpf check
    def _check_bpf_syscalls(self) -> List[Dict[str, Any]]:

        events = []

        try:
            result = subprocess.run(
                ["ausearch", "-sc", "bpf", "--start", "recent", "-i"],
                capture_output=True,
                text=True,
                timeout=5
            )

            if result.returncode != 0 and not result.stdout:
                return events

            current_record = {}
            for line in result.stdout.split('\n'):
                line = line.strip()
                if not line:
                    if current_record:
                        event = self._process_audit_record(current_record)
                        if event:
                            events.append(event)
                        current_record = {}
                    continue
                pairs = re.findall(r'(\w+)=(?:"([^"]*)"|([\S]*))', line)
                for key, quoted_val, unquoted_val in pairs:
                    current_record[key] = quoted_val if quoted_val else unquoted_val
        except subprocess.TimeoutExpired:
            pass
        except FileNotFoundError:
            pass
        except Exception as e:
            print(f"[{self.name}] auditd check error: {e}")
        return events


    # parse auditd check
    def _process_audit_record(self, record: Dict[str, str]) -> Dict[str, Any]:
        comm = record.get("comm", "unknown")
        exe = record.get("exe", "unknown")
        pid = record.get("pid", "unknown")
        uid = record.get("uid", "unknown")
        auid = record.get("auid", "unknown")
        comm_clean = comm.strip('"').split('/')[-1]

        # filter
        if comm_clean in self.bpf_whitelist:
            return None
        exe_basename = exe.strip('"').split('/')[-1]
        if exe_basename in self.bpf_whitelist:
            return None
        # return auditd events
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


    # outbound connection check flags connections and suspicious ports uses get current conn to grab conns to compare to baseline
    def _check_outbound_connections(self) -> List[Dict[str, Any]]:
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
                if dest_ip == COLLECTOR_IP:
                    continue
                if dest_ip.startswith(INTERNAL_SUBNET):
                    is_suspicious = True
                    reason = f"unexpected internal connection to {dest_ip}:{dest_port}"

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


    # grabs the connections for check
    def _get_current_connections(self) -> Set[str]:
        connections = set()

        try:
            with open("/proc/net/tcp", "r") as f:
                lines = f.readlines()[1:]  # skip header

            for line in lines:
                parts = line.split()
                if len(parts) < 10:
                    continue

                state = parts[3]
                if state != "01":
                    continue

                remote_hex = parts[2]
                dest_ip = self._hex_to_ip(remote_hex[:8])
                dest_port = int(remote_hex[9:], 16)

                inode = parts[9]
                proc_name = self._inode_to_process(inode)

                key = f"{dest_ip}|{dest_port}|{proc_name}"
                connections.add(key)
        except Exception:
            pass
        return connections


    # helper to convert hex to ip for get conn
    def _hex_to_ip(self, hex_ip: str) -> str:
        try:
            packed = bytes.fromhex(hex_ip)
            return socket.inet_ntoa(packed[::-1])
        except Exception:
            return "0.0.0.0"


    # check proc pid for who owns what socket
    def _inode_to_process(self, inode: str) -> str:
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


    # checks ebpf programs against baseline
    def _check_loaded_programs(self) -> List[Dict[str, Any]]:
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
            self._baseline_bpf_programs = current_ids

        except FileNotFoundError:
        # bpftool not installed
            pass
        except Exception as e:
            print(f"[{self.name}] bpftool check error: {e}")

        return events


    # helper that gets ebpf program ids for baseline and check
    def _get_loaded_bpf_program_ids(self) -> Set[int]:
        try:
            result = subprocess.run(
                ["bpftool", "prog", "list", "--json"],
                capture_output=True, text=True, timeout=5)
            if result.returncode == 0 and result.stdout:
                programs = json.loads(result.stdout)
                suspicious_types = {"tracepoint", "kprobe", "raw_tracepoint"}
                return {p["id"] for p in programs if p.get("type") in suspicious_types}
        except Exception:
            pass
        return set()

    
    # second ebpf helper for checks
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