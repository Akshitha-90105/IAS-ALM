
from collections import defaultdict
from datetime import datetime

# Store simulated security events
events = []
alerts = []

# Track failed SSH attempts by source IP
ssh_attempts = defaultdict(int)

# Track unique destination ports by source IP
scanned_ports = defaultdict(set)


def process_event(event):
    source_ip = event["source_ip"]
    event_type = event["event_type"]
    port = event["port"]

    events.append({
        **event,
        "timestamp": datetime.now().isoformat()
    })

    generated_alerts = []

    # 1. SSH brute-force detection
    if event_type == "ssh_failed":
        ssh_attempts[source_ip] += 1

        if ssh_attempts[source_ip] == 5:
            generated_alerts.append({
                "source_ip": source_ip,
                "type": "SSH Brute Force",
                "severity": "HIGH",
                "message": "Five failed SSH login attempts detected."
            })

    # 2. Telnet detection
    if event_type == "telnet":
        generated_alerts.append({
            "source_ip": source_ip,
            "type": "Suspicious Telnet Activity",
            "severity": "MEDIUM",
            "message": "Telnet connection attempt detected."
        })

    # 3. Port scan detection
    if event_type == "connection_attempt":
        scanned_ports[source_ip].add(port)

        if len(scanned_ports[source_ip]) == 5:
            generated_alerts.append({
                "source_ip": source_ip,
                "type": "Port Scan",
                "severity": "HIGH",
                "message": "Five different ports accessed from one IP."
            })

    alerts.extend(generated_alerts)

    return {
        "event": event,
        "alerts_generated": generated_alerts,
        "total_alerts": len(alerts)
    }


def get_alerts():
    return alerts


def get_events():
    return events
