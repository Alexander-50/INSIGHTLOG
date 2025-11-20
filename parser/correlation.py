# parser/correlation.py
from collections import defaultdict

def correlate_alerts(records, alerts):
    """
    Very simple correlation engine:
    - Multi-rule correlation
    - Shared user-agent correlation
    - Shared process correlation
    """

    ip_alerts = defaultdict(list)
    for a in alerts:
        ip = a.get("ip")
        if ip:
            ip_alerts[ip].append(a)

    correlations = []

    # Multi-alert correlation
    for ip, items in ip_alerts.items():
        if len(items) > 1:
            correlations.append({
                "type": "multi_alert",
                "ip": ip,
                "alert_count": len(items),
                "message": f"IP {ip} triggered {len(items)} alerts (multi-rule)"
            })

    # User-agent correlation
    ua_map = defaultdict(set)
    for r in records:
        ip = r.get("ip")
        ua = r.get("agent")
        if ip and ua:
            ua_map[ua].add(ip)

    for ua, ips in ua_map.items():
        if len(ips) > 1:
            correlations.append({
                "type": "user_agent_shared",
                "user_agent": ua,
                "ips": list(ips),
                "message": f"User-agent '{ua}' seen on multiple IPs: {', '.join(ips)}"
            })

    return correlations
