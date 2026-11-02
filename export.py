"""Dump a category of geosite.dat / geoip.dat as a mihomo text ruleset.

  python3 export.py site geosite.dat ru-inside out/ru-inside.txt [custom/ru-inside.txt]
  python3 export.py ip   geoip.dat   ru        out/ru.txt        [custom/ru.txt]
  python3 export.py site geosite.dat ru-inside -                  # print to stdout
  python3 export.py text category-ru.yaml out/ru-services.txt [custom/ru-services.txt] \
      [--minus out/ru-inside.txt]

`text` reads a mihomo domain ruleset (text, or yaml `payload:`) instead of a .dat.
`--minus FILE` drops every domain already covered by the rules in FILE.

Custom files: one entry per line, `#` comments. `example.com` means the domain
and its subdomains (`+.example.com`), `=example.com` only the domain itself,
`!example.com` drops it and its subdomains (`!ru` drops the whole zone),
`!=example.com` only the domain itself. For ip: CIDR, `!CIDR` drops.
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


def text(path):
    for line in open(path, encoding="utf-8"):
        line = line.split("#", 1)[0].strip()
        if line.startswith("- "):
            line = line[2:].strip().strip("'\"")
        if line and not line.endswith(":"):
            yield line.lower()


def covered(rule, by):
    # is the host part of `rule` matched by some `+.x` (x or its subdomain) or exact rule in `by`
    host = rule.removeprefix("+.")
    if rule in by:
        return True
    labels = host.split(".")
    return any("+." + ".".join(labels[i:]) in by for i in range(len(labels)))


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


kind, *args = sys.argv[1:]
minus = set()
while "--minus" in args:
    i = args.index("--minus")
    minus |= set(text(args.pop(i + 1)))
    args.pop(i)
if kind == "text":
    src, dst, *extra = args
    lines = set(text(src))
else:
    src, code, dst, *extra = args
    lines = set({"site": site, "ip": ip}[kind](entries(src, code)))
base = len(lines)
for path in extra:
    add, drop = custom(kind, path)
    lines |= add
    if kind == "ip":
        lines -= drop
    else:
        lines = {r for r in lines if not covered(r, drop)}
lines = {r for r in lines if not covered(r, minus)}
text = "\n".join(sorted(lines)) + "\n"
if dst == "-":
    sys.stdout.write(text)
else:
    open(dst, "w").write(text)
    print(f"{dst}: {len(lines)} ({base} from {src}, {len(lines) - base:+d} custom)", file=sys.stderr)
