#!/usr/bin/env python3
"""
InsightLog - integrated with timeline output
"""
import argparse
import json
import os
import time
from datetime import datetime, timezone

from parser.apache_parser import parse_apache, parse_apache_line
from parser.syslog_parser import parse_syslog, parse_syslog_line
from parser.utils import summarize_and_export, detect_suspicious_patterns, classify_severity
from parser.plotter import plot_all
from parser.live_monitor import start_live_monitor
from parser.rules_engine import RulesEngine
from parser.plugin_manager import PluginManager
from parser.burst_detector import EnhancedBurstDetector
from parser.correlation import correlate_alerts

PARSERS = {
    'apache': parse_apache,
    'syslog': parse_syslog,
}

LINE_PARSERS = {
    'apache': parse_apache_line,
    'syslog': parse_syslog_line,
}


def _to_epoch(ts):
    """Best-effort parse of timestamps used by our parsers -> epoch seconds."""
    if not ts:
        return time.time()
    # Apache: 12/Nov/2023:11:45:01 +0000 or without tz
    try:
        if '/' in ts and ':' in ts:
            if '+' in ts or '-' in ts.split()[-1]:
                return datetime.strptime(ts, "%d/%b/%Y:%H:%M:%S %z").timestamp()
            else:
                return datetime.strptime(ts, "%d/%b/%Y:%H:%M:%S").replace(tzinfo=timezone.utc).timestamp()
        # Syslog: Oct 28 10:15:24 (no year) -> assume current year
        try:
            this_year = datetime.utcnow().year
            return datetime.strptime(f"{this_year} {ts}", "%Y %b %d %H:%M:%S").replace(tzinfo=timezone.utc).timestamp()
        except Exception:
            pass
        # ISO fallback
        return datetime.fromisoformat(ts).timestamp()
    except Exception:
        return time.time()


def _iso_from_epoch(epoch):
    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()


def build_timeline(records, alerts, correlations, plugin_alerts, generated_at=None):
    """
    Merge records + alerts into a single timeline list of events (sorted chronologically).
    Each event: { timestamp: ISO, type: 'record'|'rule'|'burst'|'plugin'|'correlation', event: <name>, ip, severity, message }
    """
    events = []

    # map ip -> list of record epochs (to help timestamp alerts)
    ip_times = {}
    for r in records:
        ts = _to_epoch(r.get('timestamp'))
        ip = r.get('ip')
        ip_times.setdefault(ip, []).append(ts)
        events.append({
            "timestamp_epoch": ts,
            "timestamp": _iso_from_epoch(ts),
            "type": "record",
            "event": "record",
            "ip": ip,
            "severity": r.get("severity") or "INFO",
            "message": r.get("message") or r.get("url") or ""
        })

    # helpers to pick a timestamp for alerts (prefer latest record timestamp for same ip)
    def pick_alert_ts(alert):
        ip = alert.get("ip")
        if ip and ip in ip_times:
            return max(ip_times[ip])
        # fallback: if alert has no relation use generated_at or now
        if generated_at:
            try:
                return _to_epoch(generated_at)
            except:
                pass
        return time.time()

    # batch rule alerts and plugin alerts and bursts
    for a in (alerts or []) + (plugin_alerts or []) + (correlations or []):
        ts = pick_alert_ts(a)
        events.append({
            "timestamp_epoch": ts,
            "timestamp": _iso_from_epoch(ts),
            "type": a.get("type") or "alert",
            "event": a.get("rule") or a.get("type") or a.get("message") or "alert",
            "ip": a.get("ip"),
            "severity": (a.get("severity") or "ALERT").upper(),
            "message": a.get("message") or json.dumps(a)
        })

    # sort by epoch
    events.sort(key=lambda e: e.get("timestamp_epoch", 0))
    # convert to plain timeline without epoch
    timeline = []
    for e in events:
        timeline.append({
            "timestamp": e["timestamp"],
            "type": e["type"],
            "event": e["event"],
            "ip": e.get("ip"),
            "severity": e.get("severity"),
            "message": e.get("message")
        })
    return timeline


def print_alert(a):
    print(f"[{a.get('severity','ALERT')}] {a.get('message')}")


def main():
    ap = argparse.ArgumentParser(prog='insightlog', description='InsightLog - parse, monitor, analyze logs')
    ap.add_argument('--type', choices=PARSERS.keys(), required=True)
    ap.add_argument('--file', required=True)
    ap.add_argument('--out-json', default='output/report.json')
    ap.add_argument('--out-csv', default='output/report.csv')
    ap.add_argument('--top', type=int, default=10)
    ap.add_argument('--plot', action='store_true')
    ap.add_argument('--rules', default='rules.txt')
    ap.add_argument('--debug-rules', action='store_true')
    ap.add_argument('--live', action='store_true')
    ap.add_argument('--plugins', action='store_true')

    args = ap.parse_args()
    os.makedirs(os.path.dirname(args.out_json) or '.', exist_ok=True)

    # Engines
    engine = RulesEngine(args.rules)
    plugin_mgr = PluginManager() if args.plugins else None

    # Enhanced burst detectors
    burst_failed = EnhancedBurstDetector(metric="failed_login")
    burst_ipreq = EnhancedBurstDetector(metric="ip_requests")

    # LIVE MODE
    if args.live:
        print("[LIVE MODE] Starting real-time monitoring...")
        line_parser = LINE_PARSERS[args.type]

        def handle_record(record):
            record['severity'] = classify_severity(record)

            # Plugins live
            if plugin_mgr:
                p_alerts = plugin_mgr.run_live(record)
                for a in p_alerts:
                    print_alert(a)

            # Rules live
            r_alerts = engine.process_record(record, debug=args.debug_rules)
            for a in r_alerts:
                print_alert(a)

            # Burst detectors live
            if record.get("status") == "failed":
                b = burst_failed.process_record(record)
                if b:
                    for a in b:
                        print_alert(a)

            b2 = burst_ipreq.process_record(record)
            if b2:
                for a in b2:
                    print_alert(a)

        start_live_monitor(args.file, line_parser, handle_record)
        return

    # BATCH MODE
    parser = PARSERS[args.type]
    records = parser(args.file)
    for r in records:
        r['severity'] = classify_severity(r)

    plugin_alerts = plugin_mgr.run_batch(records) if plugin_mgr else []
    batch_alerts = engine.evaluate_batch(records, debug=args.debug_rules)

    # Burst batch
    failed_recs = [r for r in records if r.get('status') == 'failed']
    bursts = burst_failed.evaluate_batch(failed_recs)
    bursts += burst_ipreq.evaluate_batch([r for r in records if r.get('ip')])

    # Correlation engine
    correlations = correlate_alerts(records, batch_alerts + plugin_alerts + bursts)

    summary = summarize_and_export(records, top_n=args.top, out_json=args.out_json, out_csv=args.out_csv)
    patterns = detect_suspicious_patterns(records)

    # build timeline
    timeline = build_timeline(records, batch_alerts, correlations, plugin_alerts, generated_at=summary.get('generated_at'))

    result = {
        'summary': summary,
        'suspicious_patterns': patterns,
        'records': records,
        'alerts': batch_alerts + plugin_alerts + bursts,
        'correlations': correlations,
        'timeline': timeline
    }

    with open(args.out_json, 'w', encoding='utf-8') as f:
        json.dump(result, f, indent=2)

    # Print alerts
    if batch_alerts or plugin_alerts or bursts:
        print("=== Alerts ===")
        for a in (batch_alerts + plugin_alerts + bursts):
            print_alert(a)

    if correlations:
        print("=== Correlations ===")
        for c in correlations:
            print("[CORR]", c.get('message'))

    print(f"Saved report to {args.out_json} and {args.out_csv}")

    if args.plot:
        print("Generating plots...")
        plot_all(summary)


if __name__ == '__main__':
    main()
