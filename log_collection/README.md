# Cloud Security Lab - Log Collection Agent

Runs on each victim VM. Collects attack-specific logs and ships them
to the central collector VM over TLS every 5 seconds.

## File Structure

```
log_agent/
├── log_agent.py              # connects to 
├── shipper.py                # TLS log shipping to central collector
├── setup_agent.sh            # makes setup easy on server just installs whats necessary
├── collectors/
│   ├── __init__.py
│   ├── base_collector.py     # example of how to implement your collector
│   └── ebpf_collector.py     # henry attack
```

## Setup

```bash
sudo bash setup_agent.sh
```

## Run

```bash
sudo python3 log_agent.py
```

## Adding a New Collector (for teammates)

1. Create `collectors/your_attack_collector.py`
2. Subclass `BaseCollector`
3. Implement `name` property and `collect()` method
4. Optionally override `on_start()` for baseline capture
5. Import and add to `build_collectors()` in `log_agent.py`

### Minimal collector template:

```python
from collectors.base_collector import BaseCollector
from typing import List, Dict, Any

class YourCollector(BaseCollector):
    
    @property
    def name(self) -> str:
        return "your_attack_name"
    
    def on_start(self):
        # Capture baseline state
        pass
    
    def collect(self) -> List[Dict[str, Any]]:
        events = []
        # Your detection logic here
        # If suspicious:
        events.append(self.build_event(
            severity="critical",
            description="What happened",
            # any extra fields the central collector needs for mitigation
            pid=1234,
        ))
        return events
```

## Event Format

Every event shipped to the central collector looks like:

```json
{
    "alert_type": "ebpf_injection",
    "severity": "critical",
    "source_vm": "10.10.0.30",
    "timestamp": "2026-04-03T18:00:00Z",
    "shipped_at": "2026-04-03T18:00:05Z",
    "description": "Anomalous bpf() syscall from non-whitelisted process",
    "pid": "1234",
    "uid": "1000",
    "comm": "python3",
    "detection_method": "auditd_bpf_syscall"
}
```

## Network

```
Victim VMs (10.10.0.30, 10.10.0.40)
    │
    │ TLS port 8443
    ▼
Central Collector (10.10.0.20)
```
