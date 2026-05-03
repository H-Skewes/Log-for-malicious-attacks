"""
collectors/base_collector.py

Abstract base class for all log collectors.
Each attack type implements this interface to plug into the LogAgent.
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Any
from datetime import datetime


class BaseCollector(ABC):
    """
    Abstract base class for all attack-specific log collectors.
    
    To add a new attack collector:
    1. Create a new file in collectors/
    2. Subclass BaseCollector
    3. Implement collect() and name property
    4. Register it in log_agent.py
    """

    def __init__(self, vm_ip: str, config: Dict[str, Any] = None):
        """
        Args:
            vm_ip: IP address of this VM (used to identify source in logs)
            config: Optional dict of collector-specific configuration
        """
        self.vm_ip = vm_ip
        self.config = config or {}
        self._last_run = None

    @property
    @abstractmethod
    def name(self) -> str:
        """
        make a unique name for this collector depending on attack
        Used as the alert_type in log events.
        Example: 'ebpf_injection', 'arp_spoof', 'cron_abuse'
        """
        pass

    @abstractmethod
    def collect(self) -> List[Dict[str, Any]]:
        """
        Collect log events relevant to this attack type.
        
        Returns:
            List of event dicts. Each event must contain at minimum:
            {
                "alert_type": str,      # matches self.name
                "severity": str,        # "critical", "high", "medium", "low"
                "source_vm": str,       # self.vm_ip
                "timestamp": str,       # ISO format
                "description": str,     # human readable description
                ... attack-specific fields ...
            }
            Returns empty list if nothing suspicious detected.
        """
        pass

    def build_event(self, severity: str, description: str, **kwargs) -> Dict[str, Any]:
        """
        Helper to build a standardized event dict.
        Subclasses call this to ensure consistent event format.
        
        Args:
            severity: "critical", "high", "medium", "low"
            description: Human readable description of the event
            **kwargs: Any additional attack-specific fields
        
        Returns:
            Standardized event dict ready to ship to collector
        """
        event = {
            "alert_type": self.name,
            "severity": severity,
            "source_vm": self.vm_ip,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "description": description,
        }
        event.update(kwargs)
        return event

    def on_start(self):
        """
        Called once when the agent starts up.
        Override to perform any setup (e.g. baseline capture,
        initial hash computation, auditd rule installation).
        """
        pass

    def on_stop(self):
        """
        Called once when the agent shuts down.
        Override to perform cleanup.
        """
        pass

    def __repr__(self):
        return f"{self.__class__.__name__}(vm_ip={self.vm_ip}, name={self.name})"
