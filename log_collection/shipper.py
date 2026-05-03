import ssl
import socket
import json
import time
import threading
from typing import List, Dict, Any
from datetime import datetime
from collections import deque

# manages tls connection to central log collector shipping events as well
class LogShipper:
    

    # initialize var data
    def __init__(
        self,
        collector_ip: str,
        collector_port: int = 8443,
        vm_ip: str = "unknown",
        certfile: str = None,
        cafile: str = None,
        max_buffer_size: int = 1000,
        connect_timeout: int = 5,
    ):
        

        # instance variable definitions
        self.collector_ip = collector_ip
        self.collector_port = collector_port
        self.vm_ip = vm_ip
        self.certfile = certfile
        self.cafile = cafile
        self.max_buffer_size = max_buffer_size
        self.connect_timeout = connect_timeout

        self._sock = None
        self._lock = threading.Lock()
        self._buffer = deque(maxlen=max_buffer_size)
        self._connected = False
        self._total_shipped = 0
        self._total_buffered = 0



    # Builds tls context
    def _connect(self) -> bool:
        try:
            # Build SSL context
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

            if self.cafile:
                # verify server cert against our CA
                context.load_verify_locations(self.cafile)
            else:
                # skips verification for demo
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE

            if self.certfile:
                context.load_cert_chain(self.certfile)

            raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw_sock.settimeout(self.connect_timeout)
            raw_sock.connect((self.collector_ip, self.collector_port))

            self._sock = context.wrap_socket(
                raw_sock,
                server_hostname=self.collector_ip
            )
            self._connected = True
            print(f"[shipper] Connected to collector at {self.collector_ip}:{self.collector_port}")
            return True
        except (ConnectionRefusedError, socket.timeout, ssl.SSLError, OSError) as e:
            print(f"[shipper] Connection to {self.collector_ip}:{self.collector_port} failed: {e}")
            self._connected = False
            return False


    # attempt to send events over tls using connect
    def _try_send(self, events: List[Dict[str, Any]]) -> bool:
        if not self._connected:
            if not self._connect():
                return False

        payload = json.dumps(events).encode("utf-8")

        try:
            import struct
            length_prefix = struct.pack(">I", len(payload))
            self._sock.sendall(length_prefix + payload)
            return True

        except (BrokenPipeError, ConnectionResetError, ssl.SSLError, OSError) as e:
            print(f"[shipper] Send failed: {e}. Will reconnect.")
            self._disconnect()
            return False


    # prepares events for shipping then sends using try_send over tls
    def ship(self, events: List[Dict[str, Any]]) -> bool:

        if not events:
            return True

        # add logging time stamps
        for event in events:
            event.setdefault("source_vm", self.vm_ip)
            event.setdefault("shipped_at", datetime.utcnow().isoformat() + "Z")

        with self._lock:
            all_events = list(self._buffer) + events
            if self._try_send(all_events):
                self._buffer.clear()
                self._total_shipped += len(events)
                return True
            else:
                for event in events:
                    self._buffer.append(event)
                self._total_buffered += len(events)
                print(
                    f"[shipper] Buffered {len(events)} events "
                    f"(buffer size: {len(self._buffer)}/{self.max_buffer_size})"
                )
                return False


    # disconnect and close handling
    def _disconnect(self):
        """Close the current connection cleanly"""
        self._connected = False
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None
    def close(self):
        """Gracefully close the shipper"""
        with self._lock:
            self._disconnect()


    # collector stats for logging
    @property
    def stats(self) -> Dict[str, Any]:
        """Return shipping statistics"""
        return {
            "connected": self._connected,
            "collector": f"{self.collector_ip}:{self.collector_port}",
            "total_shipped": self._total_shipped,
            "total_buffered": self._total_buffered,
            "buffer_size": len(self._buffer),
        }


    # connection verification
    def __repr__(self):
        return (
            f"LogShipper(collector={self.collector_ip}:{self.collector_port}, "
            f"connected={self._connected})"
        )
