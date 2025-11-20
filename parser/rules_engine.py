# parser/rules_engine.py
import re
from collections import Counter, defaultdict
from typing import List, Dict, Any, Optional

_ops = {
    '>': lambda a, b: a > b,
    '>=': lambda a, b: a >= b,
    '<': lambda a, b: a < b,
    '<=': lambda a, b: a <= b,
    '==': lambda a, b: a == b,
    '!=': lambda a, b: a != b,
}

_rule_line_re = re.compile(
    r'^(?P<metric>\S+)(?:\s+(?P<by_ip>by_ip))?\s+(?P<op>>=|<=|!=|==|>|<)\s+(?P<val>\d+)\s+(?P<severity>\S+)',
    re.IGNORECASE
)

class Rule:
    def __init__(self, metric: str, by_ip: bool, op: str, value: int, severity: str, raw: str):
        self.metric = metric.lower()
        self.by_ip = bool(by_ip)
        self.op = op
        self.value = int(value)
        self.severity = severity.upper()
        self.raw = raw

    def matches(self, count: int) -> bool:
        return _ops[self.op](count, self.value)

    def __repr__(self):
        return "<Rule %s>" % self.raw

class RulesEngine:
    def __init__(self, rules_path: Optional[str] = "rules.txt"):
        self.rules_path = rules_path
        self.rules: List[Rule] = []
        self.global_counters: Counter = Counter()
        self.ip_counters: Dict[str, Counter] = defaultdict(Counter)
        self.metric_map = {
            'failed_login': self._metric_failed_login,
            '404': self._metric_404,
            'ip_requests': self._metric_ip_request,
        }
        if rules_path:
            try:
                self.load_rules(rules_path)
            except FileNotFoundError:
                self.rules = []

    def load_rules(self, path: str):
        self.rules = []
        with open(path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                m = _rule_line_re.match(line)
                if not m:
                    continue
                gd = m.groupdict()
                rule = Rule(
                    metric=gd['metric'],
                    by_ip=gd.get('by_ip'),
                    op=gd['op'],
                    value=int(gd['val']),
                    severity=gd['severity'],
                    raw=line
                )
                self.rules.append(rule)

    # ---------- metric functions ----------
    def _metric_failed_login(self, record):
        return 1 if record.get('status') == 'failed' else 0

    def _metric_404(self, record):
        s = record.get('status')
        return 1 if isinstance(s, int) and s == 404 else 0

    def _metric_ip_request(self, record):
        return 1 if record.get('ip') else 0

    # ---------- batch ----------
    def evaluate_batch(self, records, debug=False):
        alerts = []

        global_counts = Counter()
        per_ip_counts = defaultdict(Counter)

        for rec in records:
            for metric, fn in self.metric_map.items():
                v = fn(rec)
                if v:
                    global_counts[metric] += v
                    ip = rec.get('ip')
                    if ip:
                        per_ip_counts[ip][metric] += v

        for rule in self.rules:
            if debug:
                print("[RULE DEBUG] Evaluating rule:", rule.raw)

            if rule.by_ip:
                matched = False
                for ip, counters in per_ip_counts.items():
                    count = counters.get(rule.metric, 0)
                    if debug:
                        print("[RULE DEBUG] Checking IP %s -> count=%s threshold=%s"
                              % (ip, count, rule.value))
                    if rule.matches(count):
                        matched = True
                        alerts.append({
                            'rule': rule.raw,
                            'severity': rule.severity,
                            'type': 'per_ip',
                            'ip': ip,
                            'metric': rule.metric,
                            'count': count,
                            'message': "Rule %s triggered for %s (count=%s)" 
                                       % (rule.raw, ip, count)
                        })
                        if debug:
                            print("[RULE DEBUG] MATCH (severity=%s)" % rule.severity)
                if not matched and debug:
                    print("[RULE DEBUG] NO MATCH (per-ip checks done)")

            else:
                count = global_counts.get(rule.metric, 0)
                if debug:
                    print("[RULE DEBUG] Global count=%s threshold=%s"
                          % (count, rule.value))
                if rule.matches(count):
                    alerts.append({
                        'rule': rule.raw,
                        'severity': rule.severity,
                        'type': 'global',
                        'metric': rule.metric,
                        'count': count,
                        'message': "Rule %s triggered globally (count=%s)"
                                   % (rule.raw, count)
                    })
                    if debug:
                        print("[RULE DEBUG] MATCH (severity=%s)" % rule.severity)
                else:
                    if debug:
                        print("[RULE DEBUG] NO MATCH")

            if debug:
                print("")

        return alerts

    # ---------- live ----------
    def reset_live_state(self):
        self.global_counters = Counter()
        self.ip_counters = defaultdict(Counter)

    def process_record(self, record, debug=False):
        alerts = []
        ip = record.get('ip')

        for metric, fn in self.metric_map.items():
            inc = fn(record)
            if not inc:
                continue

            self.global_counters[metric] += inc
            if ip:
                self.ip_counters[ip][metric] += inc

            for rule in self.rules:
                if rule.metric != metric:
                    continue

                if debug:
                    print("[RULE DEBUG] Live check:", rule.raw)

                if rule.by_ip:
                    if not ip:
                        if debug:
                            print("[RULE DEBUG] NO MATCH (no IP)")
                        continue

                    count = self.ip_counters[ip].get(metric, 0)
                    if debug:
                        print("[RULE DEBUG] IP %s -> count=%s threshold=%s"
                              % (ip, count, rule.value))

                    if rule.matches(count):
                        alerts.append({
                            'rule': rule.raw,
                            'severity': rule.severity,
                            'type': 'per_ip',
                            'ip': ip,
                            'metric': metric,
                            'count': count,
                            'message': "Live: Rule %s triggered for %s (count=%s)"
                                       % (rule.raw, ip, count)
                        })
                        if debug:
                            print("[RULE DEBUG] MATCH (triggered live)")
                else:
                    count = self.global_counters.get(metric, 0)
                    if debug:
                        print("[RULE DEBUG] Global count=%s threshold=%s"
                              % (count, rule.value))
                    if rule.matches(count):
                        alerts.append({
                            'rule': rule.raw,
                            'severity': rule.severity,
                            'type': 'global',
                            'metric': metric,
                            'count': count,
                            'message': "Live: Rule %s triggered globally (count=%s)"
                                       % (rule.raw, count)
                        })
                        if debug:
                            print("[RULE DEBUG] MATCH (triggered live)")
                    else:
                        if debug:
                            print("[RULE DEBUG] NO MATCH")

                if debug:
                    print("")

        return alerts
