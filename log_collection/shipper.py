import ssl
import socket
import json
import time
import threading
from typing import List, Dict, Any
from datetime import datetime
from collections import deque


class LogShipper:
    """
    Manages the TLS connection to the central log collector and
    ships batched events reliably.

    Features:
    - Automatic reconnection on failure
    - Local event buffer when disconnected (up to max_buffer_size events)
    - Thread-safe for use from LogAgent's background thread
    """

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
        """
        Args:
            collector_ip:     IP of the central log collector VM
            collector_port:   Port the collector listens on (default 8443)
            vm_ip:            This VM's IP - included in all shipped events
            certfile:         Path to client TLS cert (optional, for mutual TLS)
            cafile:           Path to CA cert to verify server (optional)
            max_buffer_size:  Max events to buffer when disconnected
            connect_timeout:  TCP connect timeout in seconds
        """
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

    def ship(self, events: List[Dict[str, Any]]) -> bool:
        """
        Ship a list of events to the central collector.
        If not connected, buffers events and attempts reconnection.

        Args:
            events: List of event dicts from collectors

        Returns:
            True if events were sent successfully, False if buffered
        """
        if not events:
            return True

        # Stamp each event with ship time and source VM
        for event in events:
            event.setdefault("source_vm", self.vm_ip)
            event.setdefault("shipped_at", datetime.utcnow().isoformat() + "Z")

        with self._lock:
            # Try to flush buffer first, then send new events
            all_events = list(self._buffer) + events

            if self._try_send(all_events):
                self._buffer.clear()
                self._total_shipped += len(events)
                return True
            else:
                # Failed - buffer the new events for next attempt
                for event in events:
                    self._buffer.append(event)
                self._total_buffered += len(events)
                print(
                    f"[shipper] Buffered {len(events)} events "
                    f"(buffer size: {len(self._buffer)}/{self.max_buffer_size})"
                )
                return False

    def _try_send(self, events: List[Dict[str, Any]]) -> bool:
        """
        Attempt to send events over TLS. Reconnects if needed.
        Returns True on success, False on failure.
        """
        if not self._connected:
            if not self._connect():
                return False

        payload = json.dumps(events).encode("utf-8")

        try:
            # Prefix with 4-byte length
            import struct
            length_prefix = struct.pack(">I", len(payload))
            self._sock.sendall(length_prefix + payload)
            return True

        except (BrokenPipeError, ConnectionResetError, ssl.SSLError, OSError) as e:
            print(f"[shipper] Send failed: {e}. Will reconnect.")
            self._disconnect()
            return False

    def _connect(self) -> bool:
        """Establish TLS connection to collector. Returns True on success."""
        try:
            # Build SSL context
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

            if self.cafile:
                # Verify server cert against our CA
                context.load_verify_locations(self.cafile)
            else:
                # Lab environment - skip cert verification
                # In production you'd always verify
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE

            if self.certfile:
                # Mutual TLS - present client cert
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

    def __repr__(self):
        return (
            f"LogShipper(collector={self.collector_ip}:{self.collector_port}, "
            f"connected={self._connected})"
        )
