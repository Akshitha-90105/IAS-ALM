
# SENTINEL - Firewall Engine

firewall_rules = [
    {
        "id": 1,
        "name": "Allow HTTP",
        "protocol": "TCP",
        "port": 80,
        "action": "ALLOW",
        "enabled": True
    },
    {
        "id": 2,
        "name": "Allow HTTPS",
        "protocol": "TCP",
        "port": 443,
        "action": "ALLOW",
        "enabled": True
    },
    {
        "id": 3,
        "name": "Block Telnet",
        "protocol": "TCP",
        "port": 23,
        "action": "BLOCK",
        "enabled": True
    }
]


def get_rules():
    return firewall_rules


def add_rule(rule):
    rule["id"] = max(
        [r["id"] for r in firewall_rules],
        default=0
    ) + 1

    firewall_rules.append(rule)
    return rule


def evaluate_packet(packet):
    for rule in sorted(firewall_rules, key=lambda r: r["id"]):
        if not rule["enabled"]:
            continue

        protocol_match = (
            rule["protocol"] == "ANY"
            or rule["protocol"] == packet["protocol"]
        )

        port_match = (
            rule["port"] is None
            or rule["port"] == packet["port"]
        )

        if protocol_match and port_match:
            return {
                "decision": rule["action"],
                "matched_rule": rule["name"],
                "message": f"Packet {rule['action']} by firewall"
            }

    return {
        "decision": "BLOCK",
        "matched_rule": "Default Policy",
        "message": "No matching rule. Packet blocked."
    }
