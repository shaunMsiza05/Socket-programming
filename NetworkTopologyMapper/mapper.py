#!/usr/bin/env python3
"""
Network Topology Mapper
-----------------------

A practical tool to discover and visualize network topology by running multi-destination
traceroutes and merging the paths into a graph.

Features
- Multi-target traceroute over ICMP (default) or UDP (fallback)
- CIDR input (e.g., 192.168.1.0/24) with sampling to reduce noise
- Concurrency with rate limiting
- Aggregation of hops into a graph with RTT statistics
- Outputs:
    * DOT graph file (Graphviz)
    * Optional PNG/SVG rendering (if Graphviz `dot` is installed)
    * JSON export of nodes/edges/metrics
    * CSV edgelist
- Resilient to partial paths and asymmetric routing

Requirements
- Python 3.9+
- scapy (pip install scapy)
- graphviz system binary `dot` (optional for PNG/SVG rendering)

NOTE / DISCLAIMER
- Traceroute-style probing may be considered scanning on networks you don't own or
  operate. Use responsibly and lawfully. On many systems, sending/receiving ICMP or
  raw packets requires elevated privileges (sudo/Administrator).
"""
from __future__ import annotations
import argparse
import concurrent.futures
import csv
import ipaddress
import json
import os
import random
import shutil
import signal
import statistics
import subprocess
import sys
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

try:
    from scapy.all import IP, ICMP, UDP, sr, RandShort, conf
except ImportError as e:
    print("[!] scapy is required. Install with: pip install scapy", file=sys.stderr)
    raise

# --------------- Data structures ---------------
@dataclass
class Hop:
    ttl: int
    ip: str
    rtt_ms: float

@dataclass
class PathResult:
    target: str
    hops: List[Hop] = field(default_factory=list)

@dataclass
class NodeStats:
    rtts: List[float] = field(default_factory=list)

    def add(self, rtt_ms: float):
        if rtt_ms >= 0:
            self.rtts.append(rtt_ms)

    @property
    def avg(self) -> Optional[float]:
        return statistics.fmean(self.rtts) if self.rtts else None

    @property
    def p50(self) -> Optional[float]:
        return statistics.median(self.rtts) if self.rtts else None

    @property
    def p90(self) -> Optional[float]:
        if not self.rtts:
            return None
        data = sorted(self.rtts)
        k = max(0, int(0.9 * (len(data)-1)))
        return data[k]

# --------------- Core traceroute logic ---------------
def traceroute_target(
    target: str,
    max_ttl: int = 20,
    timeout: float = 2.0,
    probes_per_ttl: int = 1,
    proto: str = "icmp",
    dport_base: int = 33434,
    inter_probe: float = 0.0,
) -> PathResult:
    hops: List[Hop] = []
    conf.verb = 0  # quiet scapy

    for ttl in range(1, max_ttl + 1):
        pkts = []
        for p in range(probes_per_ttl):
            if proto == "icmp":
                pkt = IP(dst=target, ttl=ttl) / ICMP(id=os.getpid() & 0xFFFF, seq=ttl*10 + p)
            elif proto == "udp":
                dport = dport_base + ttl + p
                pkt = IP(dst=target, ttl=ttl) / UDP(sport=RandShort(), dport=dport)
            else:
                raise ValueError("proto must be 'icmp' or 'udp'")
            pkts.append(pkt)

        t0 = time.time()
        ans, _unans = sr(pkts, timeout=timeout, inter=inter_probe)
        best_ip, best_rtt = None, None
        for snd, rcv in ans:
            rtt_ms = (rcv.time - snd.sent_time) * 1000.0
            hop_ip = rcv.src
            if best_rtt is None or rtt_ms < best_rtt:
                best_rtt, best_ip = rtt_ms, hop_ip
        if best_ip:
            hops.append(Hop(ttl=ttl, ip=best_ip, rtt_ms=best_rtt))
            if best_ip == target:
                break

    return PathResult(target=target, hops=hops)

# --------------- Graph building ---------------
def build_graph(paths: List[PathResult], source_label: str = "source"):
    node_stats: Dict[str, NodeStats] = {}
    edges: Dict[Tuple[str, str], int] = {}

    for pr in paths:
        ordered, seen_ttls = [], set()
        for h in pr.hops:
            if h.ttl in seen_ttls: continue
            seen_ttls.add(h.ttl)
            ordered.append(h)
            node_stats.setdefault(h.ip, NodeStats()).add(h.rtt_ms)

        last_ip = source_label
        for hop in ordered:
            edge = (last_ip, hop.ip)
            edges[edge] = edges.get(edge, 0) + 1
            last_ip = hop.ip
        if ordered and ordered[-1].ip != pr.target:
            edge = (ordered[-1].ip, pr.target)
            edges[edge] = edges.get(edge, 0) + 1
            node_stats.setdefault(pr.target, NodeStats())
        elif not ordered:
            edge = (source_label, pr.target)
            edges[edge] = edges.get(edge, 0) + 1
            node_stats.setdefault(pr.target, NodeStats())

    node_stats.setdefault(source_label, NodeStats())
    return node_stats, edges

# --------------- DOT / CSV / JSON output ---------------
def write_dot(node_stats, edges, out_path, source_label="source"):
    def fmt_label(ip: str) -> str:
        ns = node_stats.get(ip)
        if not ns or not ns.rtts: return ip
        parts = [ip]
        if ns.avg is not None: parts.append(f"avg {ns.avg:.1f} ms")
        if ns.p50 is not None: parts.append(f"p50 {ns.p50:.1f} ms")
        if ns.p90 is not None: parts.append(f"p90 {ns.p90:.1f} ms")
        return "\\n".join(parts)

    with open(out_path, "w", encoding="utf-8") as f:
        f.write("digraph topology {\\n  rankdir=LR;\\n  node [shape=box, style=rounded];\\n")
        for ip, ns in node_stats.items():
            attrs, label = [], fmt_label(ip)
            if ip == source_label:
                attrs.append('shape=ellipse')
                attrs.append('style=\"rounded,bold\"')
            attrs.append(f'label=\"{label}\"')
            f.write(f"  \\\"{ip}\\\" [{', '.join(attrs)}];\\n")
        for (u, v), count in edges.items():
            f.write(f"  \\\"{u}\\\" -> \\\"{v}\\\" [label=\\\"{count}\\\"];\\n")
        f.write("}\\n")

def render_dot(dot_path: str, fmt: str = "png") -> Optional[str]:
    dot_bin = shutil.which("dot")
    if not dot_bin: return None
    out_path = os.path.splitext(dot_path)[0] + f".{fmt}"
    try:
        subprocess.run([dot_bin, f"-T{fmt}", dot_path, "-o", out_path], check=True)
        return out_path
    except subprocess.CalledProcessError:
        return None

def write_csv(edges, csv_path: str):
    
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["src", "dst", "count"])
        for (u, v), c in edges.items(): w.writerow([u, v, c])

def write_json(node_stats, edges, json_path: str):
    nodes = [{"id": ip, "avg_ms": ns.avg, "p50_ms": ns.p50,
              "p90_ms": ns.p90, "samples": len(ns.rtts)} for ip, ns in node_stats.items()]
    edgelist = [{"src": u, "dst": v, "count": c} for (u, v), c in edges.items()]
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump({"nodes": nodes, "edges": edgelist}, f, indent=2)

# --------------- Target selection ---------------
def expand_targets(cidrs: List[str], sample: int, shuffle: bool = True) -> List[str]:
    all_targets: List[str] = []
    for c in cidrs:
        net = ipaddress.ip_network(c, strict=False)
        hosts = [str(ip) for ip in net.hosts()]
        if shuffle: random.shuffle(hosts)
        if sample > 0: hosts = hosts[:sample]
        all_targets.extend(hosts)
    seen, uniq = set(), []
    for h in all_targets:
        if h not in seen:
            uniq.append(h); seen.add(h)
    return uniq

# --------------- Orchestration ---------------
def run_mapper(
    cidrs: List[str],
    sample: int = 64,
    max_workers: int = 200,
    max_ttl: int = 20,
    timeout: float = 2.0,
    probes_per_ttl: int = 1,
    proto: str = "icmp",
    pps: int = 500,
    inter_probe: float = 0.0,
) -> List[PathResult]:
    targets = expand_targets(cidrs, sample=sample)
    if not targets:
        print("[!] No targets to probe."); return []
    delay_between = max(0.0, 1.0 / max(1, pps))
    results: List[PathResult] = []
    stop = False

    def handle_sigint(signum, frame):
        nonlocal stop
        stop = True
        print("\\n[!] Stopping early due to Ctrl-C...", file=sys.stderr)
    signal.signal(signal.SIGINT, handle_sigint)

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = []
        for i, tgt in enumerate(targets, 1):
            if stop: break
            f = ex.submit(traceroute_target, tgt, max_ttl, timeout,
                          probes_per_ttl, proto, 33434, inter_probe)
            futures.append(f); time.sleep(delay_between)
        for f in concurrent.futures.as_completed(futures):
            try: results.append(f.result())
            except Exception as e: print(f"[!] Probe error: {e}", file=sys.stderr)
    return results

# --------------- CLI ---------------
def parse_args(argv: Optional[List[str]] = None):
    p = argparse.ArgumentParser(description="Multi-target traceroute topology mapper")
    p.add_argument("cidr", nargs="+", help="CIDR target(s), e.g. 192.168.1.0/24")
    p.add_argument("--sample", type=int, default=64, help="Max hosts to sample per CIDR (0=all)")
    p.add_argument("--max-workers", type=int, default=200, help="Concurrent traceroutes")
    p.add_argument("--max-ttl", type=int, default=20, help="Max TTL/hops")
    p.add_argument("--timeout", type=float, default=2.0, help="Per-ttl listen timeout (sec)")
    p.add_argument("--probes-per-ttl", type=int, default=1, help="Redundant probes per TTL")
    p.add_argument("--proto", choices=["icmp", "udp"], default="icmp", help="Probe protocol")
    p.add_argument("--pps", type=int, default=500, help="Submission rate (probes/sec)")
    p.add_argument("--inter-probe", type=float, default=0.0, help="Delay between probes in a TTL burst (sec)")
    p.add_argument("--out", default="topology.dot", help="DOT output path")
    p.add_argument("--render", choices=["png", "svg", "none"], default="png", help="Render DOT via Graphviz")
    p.add_argument("--json", default=None, help="Optional JSON export path")
    p.add_argument("--csv", default=None, help="Optional CSV edgelist path")
    p.add_argument("--source-label", default="source", help="Label for origin node")
    return p.parse_args(argv)

def main(argv: Optional[List[str]] = None):
    args = parse_args(argv)
    print(f"[*] Expanding targets from: {', '.join(args.cidr)}")
    results = run_mapper(args.cidr, args.sample, args.max_workers, args.max_ttl,
                         args.timeout, args.probes_per_ttl, args.proto,
                         args.pps, args.inter_probe)
    print(f"[*] Probes complete: {len(results)} targets")
    nodes, edges = build_graph(results, source_label=args.source_label)
    print(f"[*] Graph: {len(nodes)} nodes, {len(edges)} edges")
    write_dot(nodes, edges, args.out, source_label=args.source_label)
    print(f"[+] Wrote DOT: {args.out}")
    if args.render != "none":
        out_img = render_dot(args.out, fmt=args.render)
        if out_img: print(f"[+] Rendered graph: {out_img}")
        else: print("[!] Graphviz 'dot' not found or render failed.")
    if args.json: write_json(nodes, edges, args.json); print(f"[+] Wrote JSON: {args.json}")
    if args.csv: write_csv(edges, args.csv); print(f"[+] Wrote CSV: {args.csv}")

if __name__ == "__main__":
    main()
