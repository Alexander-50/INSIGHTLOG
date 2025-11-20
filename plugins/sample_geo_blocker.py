# plugins/sample_geo_blocker.py
def process_record(record):
    bad_ips = {"218.92.1.15", "192.168.1.200"}  # example blocklist
    ip = record.get("ip")
    if ip in bad_ips:
        return [{
            "rule": "geo_blocker",
            "severity": "ALERT",
            "type": "plugin",
            "ip": ip,
            "message": f"Blacklisted IP detected: {ip}"
        }]
    return []
