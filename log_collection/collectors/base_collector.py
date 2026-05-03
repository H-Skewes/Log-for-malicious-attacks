from abc import ABC, abstractmethod
from typing import List, Dict, Any
from datetime import datetime


class BaseCollector(ABC):
    """
    Abstract base class for all attack log collectors.
    """
    # define collector vars
    def __init__(self, vm_ip: str, config: Dict[str, Any] = None):
        self.vm_ip = vm_ip
        self.config = config or {}
        self._last_run = None


    # unique name of attack
    @property
    @abstractmethod
    def name(self) -> str:
        pass


    # collect attack logs
    @abstractmethod
    def collect(self) -> List[Dict[str, Any]]:
        pass
    # handle the events
    def build_event(self, severity: str, description: str, **kwargs) -> Dict[str, Any]:
        event = {
            "alert_type": self.name,
            "severity": severity,
            "source_vm": self.vm_ip,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "description": description,
        }
        event.update(kwargs)
        return event

    # typically need to set attack baseline
    def on_start(self):
        pass

    # cleanup for the collector once program stops if necessary
    def on_stop(self):
        pass
    
    
    # report naming for logging not entirely necessary
    def __repr__(self):
        return f"{self.__class__.__name__}(vm_ip={self.vm_ip}, name={self.name})"
