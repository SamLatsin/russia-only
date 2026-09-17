def varint(n):
    b = bytearray()
    while True:
        x, n = n & 0x7F, n >> 7
        b.append(x | 0x80 if n else x)
        if not n:
            return bytes(b)

def ld(num, payload):  # length-delimited
    return varint(num << 3 | 2) + varint(len(payload)) + payload

def vi(num, val):      # varint field
    return varint(num << 3) + varint(val)

# GeoSiteList{ GeoSite{ country_code="CN", domain{ type=Full, value } } }
domain = vi(1, 3) + ld(2, b"stub.invalid")
open("stub-site.dat", "wb").write(ld(1, ld(1, b"CN") + ld(2, domain)))

# GeoIPList{ GeoIP{ country_code="CN", cidr{ ip=192.0.2.0, prefix=32 } } }
cidr = ld(1, bytes([192, 0, 2, 0])) + vi(2, 32)
open("stub-ip.dat", "wb").write(ld(1, ld(1, b"CN") + ld(2, cidr)))
