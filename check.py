"""Sanity-check built mihomo text rulesets before publishing; exits 1 on any problem.

  python3 check.py domain out/ru-inside.txt out/ru-services.txt
  python3 check.py ip     out/ru.txt

domain: no rule may cover a whole zone (`+.com`, `com`, `+.*.com`) except the
ZONES below, and none may match or sit inside a FORBIDDEN domain (foreign
services that must never go DIRECT / RU).
ip: no subnet wider than /8 (IPv4) or /16 (IPv6).
"""
import ipaddress
import sys

FORBIDDEN = """
google.com youtube.com googlevideo.com telegram.org t.me whatsapp.com
instagram.com facebook.com x.com twitter.com discord.com github.com
openai.com chatgpt.com
""".split()
# Russian / regional zones allowed as a whole: .ru .su .рф .by .moscow .tatar .yandex .psk
# .москва .онлайн .сайт .орг .дети .рус
ZONES = """
ru su xn--p1ai by moscow tatar yandex psk
xn--80adxhks xn--80asehdb xn--80aswg xn--c1avg xn--d1acj3b xn--p1acf
""".split()
MIN_PREFIX = {4: 8, 6: 16}


def rules(path):
    for line in open(path, encoding="utf-8"):
        line = line.split("#", 1)[0].strip().lower()
        if line:
            yield line


def parse(rule):
    # -> (labels, matches subdomains, matches the domain itself)
    if rule.startswith("+."):
        return rule[2:].split("."), True, True
    if rule.startswith("."):
        return rule[1:].split("."), True, False
    return rule.split("."), False, True


def matches(rule, domain):
    pat, sub, exact = parse(rule)
    d = domain.split(".")
    if len(d) < len(pat) or (len(d) == len(pat) and not exact) or (len(d) > len(pat) and not sub):
        return False
    return all(p in ("*", x) for p, x in zip(pat, d[len(d) - len(pat):]))


def check_domain(path):
    for r in rules(path):
        pat = parse(r)[0]
        zone = pat
        while zone and zone[0] == "*":
            zone = zone[1:]
        if len(zone) < 2 and ".".join(zone) not in ZONES:
            yield f"{path}: too broad: {r}"
        for d in FORBIDDEN:
            if matches(r, d) or pat[-len(d.split(".")):] == d.split("."):
                yield f"{path}: {r} matches forbidden {d}"


def check_ip(path):
    for r in rules(path):
        net = ipaddress.ip_network(r, strict=False)
        if net.prefixlen < MIN_PREFIX[net.version]:
            yield f"{path}: too broad: {r}"


kind, *paths = sys.argv[1:]
errors = [e for p in paths for e in {"domain": check_domain, "ip": check_ip}[kind](p)]
for e in errors:
    print(f"::error::{e}")
print(f"{kind}: {len(errors)} problems in {', '.join(paths)}", file=sys.stderr)
sys.exit(1 if errors else 0)
