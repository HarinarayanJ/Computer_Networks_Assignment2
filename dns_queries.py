#!/usr/bin/env python3

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import OVSController
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel

from scapy.all import rdpcap, DNSQR
import time
import csv
import os

class Topology(Topo):
    def build(self):
        # Hosts
        h1 = self.addHost('h1', ip='10.0.0.1/24')
        h2 = self.addHost('h2', ip='10.0.0.2/24')
        h3 = self.addHost('h3', ip='10.0.0.3/24')
        h4 = self.addHost('h4', ip='10.0.0.4/24')
        dns = self.addHost('dns', ip='10.0.2.0/24')

        # Switches
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        s3 = self.addSwitch('s3')
        s4 = self.addSwitch('s4')

        # Links
        self.addLink(h1, s1, bw=100, delay='2ms')
        self.addLink(h2, s2, bw=100, delay='2ms')
        self.addLink(h3, s3, bw=100, delay='2ms')
        self.addLink(h4, s4, bw=100, delay='2ms')

        self.addLink(s1, s2, bw=100, delay='5ms')
        self.addLink(s2, s3, bw=100, delay='8ms')
        self.addLink(s3, s4, bw=100, delay='10ms')
        self.addLink(s2, dns, bw=100, delay='1ms')
        self.addLink(s2, intfName2='veth1')



pcap_files = {
    'h1': 'PCAP_1_H1.pcap',
    'h2': 'PCAP_2_H2.pcap',
    'h3': 'PCAP_3_H3.pcap',
    'h4': 'PCAP_4_H4.pcap',
}

output_dir = "dns_results"
os.makedirs(output_dir, exist_ok=True)

def extract_queries(txt_file):
    queries = []
    with open(txt_file, "r") as f:
        for line in f:
            domain = line.strip()
            if domain: 
                queries.append(domain)
    queries = queries[:50]
    return queries


def query_domains(host, queries):
    results = []
    for domain in queries:
        print(f"Querying {domain} on {host.name}...")
        start = time.time()
        output = host.cmd(f"nslookup {domain}")
        end = time.time()
        latency_ms = (end - start) * 1000
        success = ("Name:" in output) or ("Address" in output)
        results.append({
            "domain": domain,
            "latency_ms": latency_ms,
            "success": success
        })
    return results

def compute_metrics(results):
    t_q = len(results)
    s = sum(1 for r in results if r["success"])
    f = t_q - s
    avg_latency = sum(r["latency_ms"] for r in results) / t_q if t_q else 0
    throughput = t_q / (sum(r["latency_ms"] for r in results)/1000) if t_q else 0
    return {
        "total_queries": t_q,
        "success": s,
        "failed": f,
        "avg_latency_ms": avg_latency,
        "throughput_qps": throughput
    }

def save_results_csv(host_name, results, metrics):
    csv_file = os.path.join(output_dir, f"{host_name}_results.csv")
    with open(csv_file, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["domain", "latency_ms", "success"])
        writer.writeheader()
        writer.writerows(results)
        writer.writerow({})
        writer.writerow({"domain": "TOTAL_QUERIES", "latency_ms": metrics["total_queries"]})
        writer.writerow({"domain": "SUCCESSFUL", "latency_ms": metrics["success"]})
        writer.writerow({"domain": "FAILED", "latency_ms": metrics["failed"]})
        writer.writerow({"domain": "AVG_LATENCY_MS", "latency_ms": metrics["avg_latency_ms"]})
        writer.writerow({"domain": "THROUGHPUT_QPS", "latency_ms": metrics["throughput_qps"]})

def main():
    setLogLevel('info')

    topo = Topology()
    net = Mininet(topo=topo, link=TCLink, controller=lambda name: OVSController(name, ip='127.0.0.1', port=6633))
    net.start()
    print("[+] Network started")

    print("[+] Testing connectivity...")
    net.pingAll()

    t = 0
    for host_name, pcap_file in pcap_files.items():
        host = net.get(host_name)
        print(f"[+] Processing {host_name} with {pcap_file}")

        q = ["queries_h1.txt","queries_h2.txt","queries_h3.txt","queries_h4.txt"]
        queries = extract_queries(q[t])
        print(f"    Extracted {len(queries)} queries")

        results = query_domains(host, queries)
        metrics = compute_metrics(results)

        save_results_csv(host_name, results, metrics)
        print(f"    Metrics for {host_name}: {metrics}")
        t += 1

    CLI(net)

    net.stop()
    print("[+] Done. Results saved in folder:", output_dir)


if __name__ == "__main__":
    main()
