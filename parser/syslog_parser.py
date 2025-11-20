import re
from collections import namedtuple

SysRecord = namedtuple('SysRecord', [
    'timestamp','host','process','pid','message','ip','status'
])

IP_RE = re.compile(r'(?P<ip>\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b)')
SYSLOG_REGEX = re.compile(
    r'(?P<time>^[A-Z][a-z]{2}\s+\d+ \d{2}:\d{2}:\d{2}) '
    r'(?P<host>\S+) (?P<proc>[^:\[]+)(?:\[(?P<pid>\d+)\])?: '
    r'(?P<msg>.*)$'
)

def parse_syslog(path):
    records = []
    with open(path, 'r', errors='ignore') as f:
        for line in f:
            rec = parse_syslog_line(line)
            if rec:
                records.append(rec)
    return records


def parse_syslog_line(line):
    m = SYSLOG_REGEX.search(line)
    if not m:
        return None

    gd = m.groupdict()
    msg = gd.get("msg", "")

    ipm = IP_RE.search(msg)
    ip = ipm.group("ip") if ipm else None

    status = None
    if "failed" in msg.lower() or "invalid" in msg.lower():
        status = "failed"

    return SysRecord(
        timestamp=gd.get("time"),
        host=gd.get("host"),
        process=gd.get("proc").strip(),
        pid=gd.get("pid"),
        message=msg,
        ip=ip,
        status=status
    )._asdict()
