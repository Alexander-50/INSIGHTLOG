import re
from collections import namedtuple

ApacheRecord = namedtuple('ApacheRecord', [
    'ip','timestamp','method','url','status','size','referer','agent'
])

APACHE_REGEX = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<url>[^\s]+) [^"]+" '
    r'(?P<status>\d{3}) (?P<size>\S+) '
    r'"(?P<referer>[^"]*)" "(?P<agent>[^"]*)"'
)

def parse_apache(path):
    records = []
    with open(path, 'r', errors='ignore') as f:
        for line in f:
            rec = parse_apache_line(line)
            if rec:
                records.append(rec)
    return records


def parse_apache_line(line):
    m = APACHE_REGEX.search(line)
    if not m:
        return None

    return ApacheRecord(
        ip=m.group("ip"),
        timestamp=m.group("time"),
        method=m.group("method"),
        url=m.group("url"),
        status=int(m.group("status")),
        size=m.group("size"),
        referer=m.group("referer"),
        agent=m.group("agent")
    )._asdict()
