import ipaddress
import json
import threading
import uuid
from pathlib import Path

from flask import Flask, jsonify, render_template, request


BASE_DIR = Path(__file__).resolve().parent
DEFAULT_RULES = [
    {"id": "fw-001", "source": "10.0.0.0/8", "protocol": "TCP", "port": 22, "action": "ALLOW", "description": "Private network SSH"},
    {"id": "fw-002", "source": "10.0.0.0/8", "protocol": "TCP", "port": 443, "action": "ALLOW", "description": "Private network HTTPS"},
    {"id": "fw-003", "source": "10.0.0.0/8", "protocol": "UDP", "port": 53, "action": "ALLOW", "description": "Private network DNS"},
    {"id": "fw-004", "source": "192.168.1.0/24", "protocol": "TCP", "port": 80, "action": "ALLOW", "description": "LAN web traffic"},
    {"id": "fw-005", "source": "192.168.1.0/24", "protocol": "TCP", "port": 443, "action": "ALLOW", "description": "LAN secure web traffic"},
    {"id": "fw-006", "source": "192.168.1.0/24", "protocol": "UDP", "port": 53, "action": "ALLOW", "description": "LAN DNS"},
    {"id": "fw-007", "source": "0.0.0.0/0", "protocol": "TCP", "port": 23, "action": "DENY", "description": "Block insecure Telnet"},
    {"id": "fw-008", "source": "192.168.1.0/24", "protocol": "TCP", "port": 5432, "action": "DENY", "description": "Keep database private"},
]
SERVICES = [
    {"name": "SSH", "port": 22, "protocol": "TCP"},
    {"name": "DNS", "port": 53, "protocol": "UDP"},
    {"name": "HTTP", "port": 80, "protocol": "TCP"},
    {"name": "HTTPS", "port": 443, "protocol": "TCP"},
    {"name": "Telnet", "port": 23, "protocol": "TCP"},
    {"name": "PostgreSQL", "port": 5432, "protocol": "TCP"},
    {"name": "NTP", "port": 123, "protocol": "UDP"},
    {"name": "App service", "port": 8080, "protocol": "TCP"},
]
POLICY_LOCK = threading.Lock()


def create_app(test_config=None):
    app = Flask(__name__)
    app.config.from_mapping(RULES_PATH=BASE_DIR / "data" / "rules.json", MAX_CONTENT_LENGTH=16 * 1024)
    if test_config:
        app.config.update(test_config)

    def load_rules():
        rules_path = Path(app.config["RULES_PATH"])
        with POLICY_LOCK:
            if not rules_path.exists():
                rules_path.parent.mkdir(parents=True, exist_ok=True)
                rules_path.write_text(json.dumps(DEFAULT_RULES, indent=2) + "\n", encoding="utf-8")
            return json.loads(rules_path.read_text(encoding="utf-8"))

    def save_rules(rules):
        rules_path = Path(app.config["RULES_PATH"])
        with POLICY_LOCK:
            rules_path.parent.mkdir(parents=True, exist_ok=True)
            rules_path.write_text(json.dumps(rules, indent=2) + "\n", encoding="utf-8")

    def evaluate_address(address, rules):
        results = []
        services = list(SERVICES)
        known_services = {(service["port"], service["protocol"]) for service in services}
        for rule in rules:
            service_key = (rule["port"], rule["protocol"])
            if service_key not in known_services:
                services.append({"name": "Custom service", "port": rule["port"], "protocol": rule["protocol"]})
                known_services.add(service_key)

        for service in services:
            matched_rule = None
            for rule in rules:
                network = ipaddress.ip_network(rule["source"], strict=False)
                if (address.version == network.version and address in network
                        and rule["protocol"] == service["protocol"] and rule["port"] == service["port"]):
                    matched_rule = rule
                    break
            results.append({
                **service,
                "action": matched_rule["action"] if matched_rule else "DENY",
                "rule_id": matched_rule["id"] if matched_rule else None,
                "reason": matched_rule["description"] if matched_rule else "Default deny",
                "source": matched_rule["source"] if matched_rule else None,
            })

        allowed = sum(result["action"] == "ALLOW" for result in results)
        return {"ip": str(address), "results": results,
                "summary": {"allowed": allowed, "denied": len(results) - allowed}}

    @app.get("/")
    def index():
        rules = load_rules()
        return render_template("index.html", rules=rules, rule_count=len(rules),
                               allow_count=sum(rule["action"] == "ALLOW" for rule in rules),
                               deny_count=sum(rule["action"] == "DENY" for rule in rules))

    @app.post("/api/evaluate")
    def evaluate():
        payload = request.get_json(silent=True) or {}
        try:
            address = ipaddress.ip_address(payload.get("ip", ""))
        except ValueError:
            return jsonify({"error": "Enter a valid IPv4 or IPv6 address."}), 400
        return jsonify(evaluate_address(address, load_rules()))

    @app.post("/api/rules")
    def add_rule():
        payload = request.get_json(silent=True) or {}
        try:
            source = str(ipaddress.ip_network(payload.get("source", ""), strict=False))
            port = int(payload.get("port", ""))
        except (ValueError, TypeError):
            return jsonify({"error": "Enter a valid IP address or CIDR range and port."}), 400

        protocol = str(payload.get("protocol", "")).upper()
        action = str(payload.get("action", "")).upper()
        if not 1 <= port <= 65535:
            return jsonify({"error": "Port must be between 1 and 65535."}), 400
        if protocol not in {"TCP", "UDP"}:
            return jsonify({"error": "Protocol must be TCP or UDP."}), 400
        if action not in {"ALLOW", "DENY"}:
            return jsonify({"error": "Permission must be ALLOW or DENY."}), 400

        rule = {"id": f"fw-{uuid.uuid4().hex[:8]}", "source": source, "protocol": protocol,
                "port": port, "action": action,
                "description": str(payload.get("description", "Manual policy rule")).strip()[:80]
                or "Manual policy rule"}
        rules = load_rules()
        rules.insert(0, rule)
        save_rules(rules)
        return jsonify({"rule": rule}), 201

    @app.delete("/api/rules/<rule_id>")
    def delete_rule(rule_id):
        rules = load_rules()
        remaining = [rule for rule in rules if rule["id"] != rule_id]
        if len(remaining) == len(rules):
            return jsonify({"error": "Rule not found."}), 404
        save_rules(remaining)
        return jsonify({"deleted": rule_id})

    return app


app = create_app()


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)