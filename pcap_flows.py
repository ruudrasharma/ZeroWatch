"""
ZeroWatch - real traffic: turn a packet capture into the flows the model scores.

Reads classic .pcap files with the standard library only (no scapy in the serving image),
rebuilds connections, and derives the same 20 features as the data contract:

  per connection    duration, protocol, service (from the destination port), TCP state flag,
                    bytes each way
  last two seconds  count, srv_count, serror_rate, rerror_rate, same_srv_rate, diff_srv_rate
  last 255 conns    dst_host_count, dst_host_srv_count, dst_host_serror_rate

Four contract features describe what happened INSIDE the session (hot, num_failed_logins,
root_shell, logged_in). Packets alone cannot reveal them, least of all under TLS, so the first
three are 0 and logged_in is approximated as "the handshake completed and the server sent data".

It also builds the host graph: who talked to whom, and which sources behave like scanners
or flooders across many flows (something no single flow can show).
"""
from __future__ import annotations

import socket
import struct
from collections import deque

MAX_PACKETS = 200_000
PORTS = {20: "ftp_data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 43: "whois", 53: "domain", 79: "finger",
         80: "http", 8080: "http", 8000: "http", 110: "pop_3", 111: "sunrpc", 119: "nntp", 139: "netbios_ssn",
         143: "imap4", 179: "bgp", 389: "ldap", 443: "http_443", 513: "login", 514: "shell", 515: "printer",
         6000: "X11", 6667: "IRC"}
UDP_PORTS = {53: "domain_u", 69: "tftp_u", 123: "ntp_u", 137: "netbios_ns", 138: "netbios_dgm"}
SERROR = {"S0", "S1", "S2", "S3", "SH"}
RERROR = {"REJ", "RSTR", "RSTOS0"}
FIN, SYN, RST, ACK = 0x01, 0x02, 0x04, 0x10


class PcapError(ValueError):
    pass


def parse_pcap(data: bytes) -> list[dict]:
    """Classic pcap -> list of IPv4 packets {ts, src, dst, proto, sport, dport, flags, size}."""
    if len(data) < 24:
        raise PcapError("File is too small to be a packet capture.")
    magic = data[:4]
    if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        end = "<"
    elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        end = ">"
    elif magic == b"\x0a\x0d\x0d\x0a":
        raise PcapError("This is a pcapng file. Convert it first: tshark -F pcap -r in.pcapng -w out.pcap")
    else:
        raise PcapError("Not a pcap file (unknown magic number).")
    nano = magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
    linktype = struct.unpack(end + "I", data[20:24])[0]
    skip = {1: 14, 101: 0, 113: 16, 0: 4}.get(linktype)
    if skip is None:
        raise PcapError(f"Unsupported link type {linktype}; Ethernet, raw IP and Linux cooked captures are supported.")
    out, off = [], 24
    while off + 16 <= len(data) and len(out) < MAX_PACKETS:
        sec, frac, caplen, _orig = struct.unpack(end + "IIII", data[off:off + 16])
        frame = data[off + 16: off + 16 + caplen]
        off += 16 + caplen
        if linktype == 1:
            if len(frame) < 14:
                continue
            etype = struct.unpack("!H", frame[12:14])[0]
            hdr = 14
            if etype == 0x8100 and len(frame) >= 18:  # VLAN tag
                etype, hdr = struct.unpack("!H", frame[16:18])[0], 18
            if etype != 0x0800:
                continue
            ip = frame[hdr:]
        else:
            ip = frame[skip:]
        if len(ip) < 20 or ip[0] >> 4 != 4:
            continue
        ihl, total, proto = (ip[0] & 0x0F) * 4, struct.unpack("!H", ip[2:4])[0], ip[9]
        pkt = {"ts": sec + frac / (1e9 if nano else 1e6), "src": socket.inet_ntoa(ip[12:16]),
               "dst": socket.inet_ntoa(ip[16:20]), "sport": 0, "dport": 0, "flags": 0, "size": 0}
        seg = ip[ihl:]
        if proto == 6 and len(seg) >= 20:
            pkt["proto"] = "tcp"
            pkt["sport"], pkt["dport"] = struct.unpack("!HH", seg[:4])
            pkt["flags"] = seg[13]
            pkt["size"] = max(0, total - ihl - (seg[12] >> 4) * 4)
        elif proto == 17 and len(seg) >= 8:
            pkt["proto"] = "udp"
            pkt["sport"], pkt["dport"] = struct.unpack("!HH", seg[:4])
            pkt["size"] = max(0, total - ihl - 8)
        elif proto == 1 and len(seg) >= 4:
            pkt["proto"] = "icmp"
            pkt["dport"] = seg[0]  # ICMP type
            pkt["size"] = max(0, total - ihl - 8)
        else:
            continue
        out.append(pkt)
    if not out:
        raise PcapError("The capture contains no IPv4 TCP, UDP or ICMP packets.")
    return out


def _tcp_flag(c: dict) -> str:
    """Zeek/KDD connection states from the TCP flags each side sent."""
    if not c["syn"]:
        return "OTH"                      # joined mid-stream
    if not c["synack"]:
        if c["r_rst"]:
            return "REJ"                  # SYN answered with RST: port closed
        if c["o_rst"]:
            return "RSTOS0"
        return "SH" if c["o_fin"] else "S0"  # S0: SYN never answered
    if c["o_rst"]:
        return "RSTO"
    if c["r_rst"]:
        return "RSTR"
    if c["o_fin"] and c["r_fin"]:
        return "SF"                       # normal open and close
    if c["o_fin"]:
        return "S2"
    if c["r_fin"]:
        return "S3"
    return "S1"                           # established, never closed


def connections(packets: list[dict]) -> list[dict]:
    conns, live = [], {}
    for p in sorted(packets, key=lambda p: p["ts"]):
        fwd = (p["proto"], p["src"], p["sport"], p["dst"], p["dport"])
        rev = (p["proto"], p["dst"], p["dport"], p["src"], p["sport"])
        c = live.get(fwd) or live.get(rev)
        if c and (p["ts"] - c["end"] > 60 or (p["proto"] == "tcp" and p["flags"] & SYN and not p["flags"] & ACK
                                              and c["closed"])):
            c = None                      # idle timeout or a fresh SYN on a reused port pair
        if c is None:
            c = {"proto": p["proto"], "src": p["src"], "sport": p["sport"], "dst": p["dst"], "dport": p["dport"],
                 "start": p["ts"], "end": p["ts"], "src_bytes": 0, "dst_bytes": 0, "syn": False, "synack": False,
                 "o_fin": False, "r_fin": False, "o_rst": False, "r_rst": False, "closed": False}
            live[fwd] = c
            conns.append(c)
        orig = p["src"] == c["src"] and p["sport"] == c["sport"]
        c["end"] = p["ts"]
        c["src_bytes" if orig else "dst_bytes"] += p["size"]
        f = p["flags"]
        if p["proto"] == "tcp":
            if f & SYN and not f & ACK and orig:
                c["syn"] = True
            if f & SYN and f & ACK and not orig:
                c["synack"] = True
            if f & FIN:
                c["o_fin" if orig else "r_fin"] = True
            if f & RST:
                c["o_rst" if orig else "r_rst"] = True
            c["closed"] = c["closed"] or bool(f & (FIN | RST))
    return conns


def to_flows(conns: list[dict]) -> list[dict]:
    """Connections -> contract flows (with src/dst kept alongside for the host graph)."""
    out, recent, last = [], deque(), deque(maxlen=255)
    for c in sorted(conns, key=lambda c: c["start"]):
        if c["proto"] == "tcp":
            flag, service = _tcp_flag(c), PORTS.get(c["dport"], "private")
        elif c["proto"] == "udp":
            flag, service = "SF", UDP_PORTS.get(c["dport"], "private")
        else:
            flag, service = "SF", {8: "eco_i", 0: "ecr_i"}.get(c["dport"], "urp_i")
        while recent and c["start"] - recent[0][0] > 2:
            recent.popleft()
        recent.append((c["start"], c["dst"], service, flag))
        same_host = [r for r in recent if r[1] == c["dst"]]
        same_srv = [r for r in recent if r[2] == service]
        last.append((c["dst"], service, flag))
        host = [r for r in last if r[0] == c["dst"]]
        n = len(same_host)
        flow = {
            "duration": min(86400, int(c["end"] - c["start"])), "protocol_type": c["proto"], "service": service,
            "flag": flag, "src_bytes": min(c["src_bytes"], 2_000_000_000), "dst_bytes": min(c["dst_bytes"], 2_000_000_000),
            "logged_in": int(flag == "SF" and c["proto"] == "tcp" and c["dst_bytes"] > 0),
            "wrong_fragment": 0, "hot": 0, "num_failed_logins": 0, "root_shell": 0,
            "count": min(n, 511), "srv_count": min(len(same_srv), 511),
            "serror_rate": round(sum(r[3] in SERROR for r in same_host) / n, 2),
            "rerror_rate": round(sum(r[3] in RERROR for r in same_host) / n, 2),
            "same_srv_rate": round(sum(r[2] == service for r in same_host) / n, 2),
            "diff_srv_rate": round(sum(r[2] != service for r in same_host) / n, 2),
            "dst_host_count": len(host), "dst_host_srv_count": sum(r[1] == service for r in host),
            "dst_host_serror_rate": round(sum(r[2] in SERROR for r in host) / len(host), 2),
        }
        out.append({"flow": flow, "src": c["src"], "dst": c["dst"], "dport": c["dport"], "start": round(c["start"], 3)})
    return out


def host_graph(items: list[dict], results: list[dict]) -> dict:
    """Who talked to whom. A source is judged on all of its flows together:
    scanner = many distinct ports or hosts, mostly failed; flooder = a burst at one host, mostly failed."""
    src: dict = {}
    edges: dict = {}
    for it, r in zip(items, results, strict=True):
        s = src.setdefault(it["src"], {"flows": 0, "hosts": set(), "ports": set(), "failed": 0, "flagged": 0,
                                       "risk": 0, "per_host": {}})
        s["flows"] += 1
        s["hosts"].add(it["dst"])
        s["ports"].add((it["dst"], it["dport"]))
        s["failed"] += it["flow"]["flag"] in SERROR | RERROR | {"RSTO"}
        s["flagged"] += r["verdict"] in ("attack", "zero_day_suspect")
        s["risk"] += r["risk_score"]
        s["per_host"][it["dst"]] = s["per_host"].get(it["dst"], 0) + 1
        e = edges.setdefault((it["src"], it["dst"]), {"flows": 0, "max_risk": 0})
        e["flows"] += 1
        e["max_risk"] = max(e["max_risk"], r["risk_score"])
    sources = []
    for ip, s in src.items():
        failed = s["failed"] / s["flows"]
        if (len(s["ports"]) >= 15 or len(s["hosts"]) >= 10) and failed >= 0.5:
            role = "scanner"
        elif max(s["per_host"].values()) >= 40 and failed >= 0.5:
            role = "flooder"
        else:
            role = "normal"
        mean = s["risk"] / s["flows"]
        sources.append({"ip": ip, "flows": s["flows"], "distinct_hosts": len(s["hosts"]), "distinct_ports": len(s["ports"]),
                        "failed_share": round(failed, 2), "flagged": s["flagged"], "mean_risk": round(mean),
                        "behaviour": role, "source_risk": round(max(mean, 85 if role != "normal" else 0))})
    sources.sort(key=lambda s: (-s["source_risk"], -s["flows"]))
    top = sorted(edges.items(), key=lambda kv: (-kv[1]["max_risk"], -kv[1]["flows"]))[:60]
    return {"sources": sources[:25], "hosts": len({i["dst"] for i in items} | set(src)),
            "edges": [{"src": a, "dst": b, **e} for (a, b), e in top]}


def write_pcap(packets: list[tuple]) -> bytes:
    """Build a small Ethernet pcap from (ts, src, dst, proto, sport, dport, tcp_flags, payload_len).
    Used to generate data/sample_capture.pcap and by the tests."""
    out = [struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)]
    for ts, src, dst, proto, sport, dport, flags, size in packets:
        if proto == "tcp":
            seg = struct.pack("!HHIIBBHHH", sport, dport, 0, 0, 5 << 4, flags, 8192, 0, 0) + b"\x00" * size
            num = 6
        elif proto == "udp":
            seg = struct.pack("!HHHH", sport, dport, 8 + size, 0) + b"\x00" * size
            num = 17
        else:
            seg = struct.pack("!BBHI", dport, 0, 0, 0) + b"\x00" * size
            num = 1
        ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(seg), 0, 0, 64, num, 0,
                         socket.inet_aton(src), socket.inet_aton(dst)) + seg
        frame = b"\x00" * 12 + b"\x08\x00" + ip
        out.append(struct.pack("<IIII", int(ts), int((ts % 1) * 1e6), len(frame), len(frame)) + frame)
    return b"".join(out)
