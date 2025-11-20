# parser/burst_detector.py
from collections import defaultdict, deque
from datetime import datetime, timezone
import time

def _to_epoch(ts):
    """Convert timestamps from Apache/syslog to epoch."""
    if not ts:
        return time.time()
    try:
        # Apache format
        if '/' in ts and ':' in ts:
            if '+' in ts or '-' in ts.split()[-1]:
                dt = datetime.strptime(ts, "%d/%b/%Y:%H:%M:%S %z")
                return dt.timestamp()
            else:
                dt = datetime.strptime(ts, "%d/%b/%Y:%H:%M:%S")
                return dt.replace(tzinfo=timezone.utc).timestamp()
        # Syslog format
        try:
            year = datetime.utcnow().year
            dt = datetime.strptime(f"{year} {ts}", "%Y %b %d %H:%M:%S")
            return dt.replace(tzinfo=timezone.utc).timestamp()
        except:
            pass
        # ISO fallback
        dt = datetime.fromisoformat(ts)
        return dt.timestamp()
    except:
        return time.time()


class EnhancedBurstDetector:
    def __init__(self, metric="failed_login"):
        self.metric = metric

        # Multi-window buckets
        self.windows = {
            5: defaultdict(deque),     
            30: defaultdict(deque),    
            300: defaultdict(deque),   
        }

        # Adaptive per-IP baseline
        self.baseline = defaultdict(lambda: 1)

        # Global distributed bucket
        self.global_bucket = defaultdict(deque)

    def _update_window(self, ip, ts):
        """Append timestamp to each window."""
        results = {}
        for sec, table in self.windows.items():
            dq = table[ip]
            dq.append(ts)

            cutoff = ts - sec
            while dq and dq[0] < cutoff:
                dq.popleft()

            results[sec] = len(dq)
        return results

    def _update_global(self, ts):
        dq = self.global_bucket["global"]
        dq.append(ts)

        cutoff = ts - 10
        while dq and dq[0] < cutoff:
            dq.popleft()

        return len(dq)

    def _adaptive_threshold(self, ip):
        base = self.baseline[ip]
        return max(3, int(base * 1.7))

    def process_record(self, record):
        ip = record.get("ip")
        if not ip:
            return None

        ts = _to_epoch(record.get("timestamp"))

        # Update rolling baseline
        self.baseline[ip] = (self.baseline[ip] * 0.9) + 0.1

        win_results = self._update_window(ip, ts)
        global_count = self._update_global(ts)
        threshold = self._adaptive_threshold(ip)

        alerts = []

        triggered = [w for w, c in win_results.items() if c >= threshold]

        if triggered:
            if len(triggered) == 1:
                sev = "WARNING"
            elif len(triggered) == 2:
                sev = "ALERT"
            else:
                sev = "CRITICAL"

            alerts.append({
                "type": "burst",
                "metric": self.metric,
                "ip": ip,
                "windows_triggered": triggered,
                "counts": win_results,
                "threshold": threshold,
                "severity": sev,
                "message": (
                    f"Burst detected for {ip}: "
                    f"{', '.join([str(w)+'s' for w in triggered])} windows exceeded {threshold}"
                )
            })

        if global_count >= 8:
            alerts.append({
                "type": "distributed_burst",
                "severity": "CRITICAL",
                "window": "10s",
                "count": global_count,
                "message": "Distributed low-frequency burst attack detected"
            })

        return alerts or None

    def evaluate_batch(self, records):
        out = []
        for rec in records:
            a = self.process_record(rec)
            if a:
                out.extend(a)
        return out
