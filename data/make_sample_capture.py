"""Generate data/sample_capture.pcap: a small SYNTHETIC capture for the Capture tab.
30 seconds on a /24: ordinary web, DNS and mail traffic, then a port scan from 10.0.0.66
and a SYN flood from 10.0.0.99 against the web server. Usage: python data/make_sample_capture.py
"""
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent))
from pcap_flows import write_pcap  # noqa: E402

S, SA, A, PA, FA, R = 0x02, 0x12, 0x10, 0x18, 0x11, 0x14
rng = random.Random(7)
WEB, MAIL, DNS = "10.0.0.10", "10.0.0.25", "10.0.0.53"
pk = []


def session(t, c, server, port, up, down):
    sp = rng.randint(20000, 60000)
    pk.extend([(t, c, server, "tcp", sp, port, S, 0), (t + .01, server, c, "tcp", port, sp, SA, 0),
               (t + .02, c, server, "tcp", sp, port, A, 0), (t + .03, c, server, "tcp", sp, port, PA, up),
               (t + .08, server, c, "tcp", port, sp, PA, down), (t + .10, c, server, "tcp", sp, port, FA, 0),
               (t + .11, server, c, "tcp", port, sp, FA, 0)])


for i in range(90):                                   # normal users
    c, t = f"10.0.0.{rng.randint(100, 120)}", rng.uniform(0, 30)
    kind = rng.random()
    if kind < 0.6:
        session(t, c, WEB, 80, rng.randint(180, 400), rng.randint(900, 4000))
    elif kind < 0.75:
        session(t, c, MAIL, 25, rng.randint(400, 3000), rng.randint(200, 500))
    else:
        sp = rng.randint(20000, 60000)
        pk.extend([(t, c, DNS, "udp", sp, 53, 0, 44), (t + .005, DNS, c, "udp", 53, sp, 0, 120)])
for port in rng.sample(range(1, 1024), 60):           # port scan: closed ports answer with RST
    t = 12 + rng.uniform(0, 1.5)
    sp = rng.randint(20000, 60000)
    pk.extend([(t, "10.0.0.66", MAIL, "tcp", sp, port, S, 0), (t + .002, MAIL, "10.0.0.66", "tcp", port, sp, R, 0)])
for i in range(160):                                  # SYN flood: never completes the handshake
    pk.append((20 + i * 0.01, "10.0.0.99", WEB, "tcp", 1024 + i, 80, S, 0))

(ROOT / "sample_capture.pcap").write_bytes(write_pcap(sorted(pk)))
print(f"wrote sample_capture.pcap with {len(pk)} packets")
