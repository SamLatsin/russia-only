"""Dump a category of geosite.dat / geoip.dat as a mihomo text ruleset.

  python3 export.py site geosite.dat ru-inside out/ru-inside.txt [custom/ru-inside.txt]
  python3 export.py ip   geoip.dat   ru        out/ru.txt        [custom/ru.txt]
  python3 export.py site geosite.dat ru-inside -                  # print to stdout

Custom files: one entry per line, `#` comments. `example.com` means the domain
and its subdomains (`+.example.com`), `=example.com` only the domain itself,
`!example.com` drops it from the result. For ip: CIDR, `!CIDR` drops.
Then `mihomo convert-ruleset domain|ipcidr text <txt> <mrs>`.
"""
import ipaddress
import sys


def varint(b, i):
    r = s = 0
    while True:
        c = b[i]
        i += 1
        r |= (c & 0x7F) << s
        s += 7
        if c < 0x80:
            return r, i


def fields(b):
    i = 0
    while i < len(b):
        k, i = varint(b, i)
        f, t = k >> 3, k & 7
        if t == 0:
            v, i = varint(b, i)
        elif t == 2:
            n, i = varint(b, i)
            v, i = b[i:i + n], i + n
        else:
            raise ValueError(f"wire type {t}")
        yield f, v


def entries(path, code):
    for _, e in fields(open(path, "rb").read()):
        items = list(fields(e))
        if any(f == 1 and v.decode().lower() == code.lower() for f, v in items):
            return [v for f, v in items if f == 2]
    sys.exit(f"{code}: no such category in {path}")


def site(items):
    # Domain{type=1, value=2}: 0 keyword, 1 regex, 2 domain+subdomains, 3 full
    for d in items:
        d = dict(fields(d))
        t, v = d.get(1, 0), d[2].decode()
        if t == 2:
            yield "+." + v
        elif t == 3:
            yield v
        else:
            print(f"skip {('keyword', 'regex')[t]}: {v}", file=sys.stderr)


def ip(items):
    # CIDR{ip=1, prefix=2}
    for c in items:
        c = dict(fields(c))
        yield str(ipaddress.ip_network((ipaddress.ip_address(c[1]), c.get(2, 0))))


def custom(kind, path):
    add, drop = set(), set()
    for line in open(path, encoding="utf-8"):
        line = line.split("#", 1)[0].strip().lower()
        if not line:
            continue
        neg = line.startswith("!")
        line = line.lstrip("!")
        if kind == "ip":
            line = str(ipaddress.ip_network(line, strict=False))
        elif line.startswith("="):
            line = line[1:]
        elif not line.startswith("+."):
            line = "+." + line
        (drop if neg else add).add(line)
    return add, drop


kind, src, code, dst, *extra = sys.argv[1:]
lines = set({"site": site, "ip": ip}[kind](entries(src, code)))
base = len(lines)
for path in extra:
    add, drop = custom(kind, path)
    lines = (lines | add) - drop
text = "\n".join(sorted(lines)) + "\n"
if dst == "-":
    sys.stdout.write(text)
else:
    open(dst, "w").write(text)
    print(f"{dst}: {len(lines)} ({base} from {src}, {len(lines) - base:+d} custom)", file=sys.stderr)
