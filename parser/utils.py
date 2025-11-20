import csv
from collections import Counter
from datetime import datetime


def summarize_and_export(records, top_n=10, out_json='output/report.json', out_csv='output/report.csv'):
    ips = [r.get('ip') for r in records if r.get('ip')]
    ip_counts = Counter(ips)

    statuses = [r.get('status') for r in records if r.get('status') is not None and isinstance(r.get('status'), int)]
    status_counts = Counter(statuses)

    urls = [r.get('url') for r in records if r.get('url')]
    url_counts = Counter(urls)

    summary = {
        'top_ips': ip_counts.most_common(top_n),
        'status_counts': status_counts.most_common(),
        'top_urls': url_counts.most_common(top_n),
        'total_records': len(records),
        'generated_at': datetime.utcnow().isoformat() + 'Z'
    }

    # Export CSV safely
    try:
        keys = set()
        for r in records:
            keys.update(r.keys())
        keys = sorted(keys)

        with open(out_csv, 'w', newline='', encoding='utf-8') as csvf:
            writer = csv.DictWriter(csvf, fieldnames=keys)
            writer.writeheader()
            for r in records:
                writer.writerow({k: (r.get(k) if r.get(k) is not None else '') for k in keys})
    except Exception:
        pass

    return summary


def detect_suspicious_patterns(records):
    patterns = {}

    # 404 floods
    ip_404 = Counter([r.get('ip') for r in records if r.get('status') == 404])
    patterns['404_flood_candidates'] = ip_404.most_common(10)

    # failed login attempts
    failed_ips = Counter([r.get('ip') for r in records if r.get('status') == 'failed'])
    patterns['failed_login_candidates'] = failed_ips.most_common(10)

    return patterns


def classify_severity(record):
    """
    Determines severity level for each log entry.
    """

    # SYSLOG logic
    msg = record.get("message", "") or ""

    if record.get("status") == "failed":
        return "ALERT"

    if "invalid user" in msg.lower():
        return "WARNING"

    if "did not receive identification" in msg.lower():
        return "WARNING"

    # APACHE logic
    if isinstance(record.get("status"), int):
        code = record["status"]

        if 500 <= code < 600:
            return "CRITICAL"
        if 400 <= code < 500:
            return "WARNING"
        if code == 200:
            return "INFO"

    return "INFO"
