from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import OVSController
from mininet.nodelib import NAT
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink
import sys
import os
import time
import json
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'resolver'))

class Topology(Topo):
    def build(self):
        # Switches
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        s3 = self.addSwitch('s3')
        s4 = self.addSwitch('s4')

        # Hosts
        h1 = self.addHost('h1', ip='10.0.0.1/24')
        h2 = self.addHost('h2', ip='10.0.0.2/24')
        h3 = self.addHost('h3', ip='10.0.0.3/24')
        h4 = self.addHost('h4', ip='10.0.0.4/24')
        dns = self.addHost('dns', ip='10.0.0.5/24')

        # Links
        self.addLink(h1, s1, cls=TCLink, bw=100, delay='2ms')
        self.addLink(h2, s2, cls=TCLink, bw=100, delay='2ms')
        self.addLink(h3, s3, cls=TCLink, bw=100, delay='2ms')
        self.addLink(h4, s4, cls=TCLink, bw=100, delay='2ms')
        self.addLink(dns, s2, cls=TCLink, bw=100, delay='1ms')
        self.addLink(s1, s2, cls=TCLink, bw=100, delay='5ms')
        self.addLink(s2, s3, cls=TCLink, bw=100, delay='8ms')
        self.addLink(s3, s4, cls=TCLink, bw=100, delay='10ms')
        
        # Add NAT node
        nat = self.addNode('nat0', cls=NAT, ip='10.0.0.254/24', 
                          subnet='10.0.0.0/24', inNamespace=False)
        self.addLink(nat, s2)


def extract_domains(file):
    domains = set()

    with open(file, 'r') as f:
        for line in f:
            domain = line.strip()
            if domain:
                domains.add(domain)
    return list(domains)


def resolve_domain(host, domain, dns_server='8.8.8.8', timeout=5):

    result = {
        'domain': domain,
        'ip_address': None,
        'success': False,
        'latency': None,
        'bytes_transferred': 0
    }
    
    # Use nslookup for DNS resolution with timing
    c = f"timeout {timeout} nslookup {domain} {dns_server}"
    
    start_time = time.time()
    try:
        output = host.cmd(c)
        end_time = time.time()
        
        latency = (end_time - start_time) * 1000
        result['latency'] = latency
        result['bytes_transferred'] = len(output)
        
        
        if "server can't find" in output.lower() or "nxdomain" in output.lower() or "timed out" in output.lower() or "timeout" in output.lower() or "connection timed out" in output.lower() or "no servers could be reached" in output.lower() or "network unreachable" in output.lower():
            result['success'] = False
        else:
            result['success'] = True
        
    except Exception as e:
        end_time = time.time()
        result['latency'] = (end_time - start_time) * 1000
        result['error'] = str(e)
        result['success'] = False
    
    return result


def test_dns_resolution(net, host_name, file, dns_server='8.8.8.8'):

    print(f"Testing DNS resolution for {host_name.upper()}")
    print(f"PCAP file: {file}")
    print(f"DNS Server: {dns_server}")
    
    host = net.get(host_name)
    domains = extract_domains(file)
    
    if not domains:
        print(f"No domains found in {file}")
        return {
            'host': host_name,
            'file': file,
            'total_queries': 0,
            'successful_queries': 0,
            'failed_queries': 0,
            'average_latency_ms': 0,
            'average_throughput_bps': 0,
            'domains_tested': [],
            'results': []
        }
    
    print(f"\nResolving {len(domains)} domains...")
    
    results = []
    successful = 0
    failed = 0
    total_latency = 0
    total_bytes = 0
    total_time = 0
    
    for i, domain in enumerate(domains, 1):
        print(f"[{i}/{len(domains)}] Resolving {domain}...", end=' ')
        
        result = resolve_domain(host, domain, dns_server)
        results.append(result)
        
        if result['success']:
            successful += 1
            total_latency += result['latency']
            total_bytes += result['bytes_transferred']
            total_time += result['latency'] / 1000 
            print(f"Success (IP: {result['ip_address']}, Latency: {result['latency']:.2f} ms)")
        else:
            failed += 1
            print(f"Failed ({result['error']})")
    
    avg_latency = total_latency / successful if successful > 0 else 0
    avg_throughput = (total_bytes * 8) / total_time if total_time > 0 else 0
    
    results = {
        'host': host_name,
        'file': file,
        'total_queries': len(domains),
        'successful_queries': successful,
        'failed_queries': failed,
        'average_latency_ms': round(avg_latency, 2),
        'average_throughput_bps': round(avg_throughput, 2),
        'domains_tested': domains,
        'results': results
    }
    
    print(f"Statistics for {host_name.upper()}:")
    print(f"  Total Queries: {results['total_queries']}")
    print(f"  Successful: {results['successful_queries']}")
    print(f"  Failed: {results['failed_queries']}")
    print(f"  Success Rate: {(successful/len(domains)*100):.1f}%")
    print(f"  Average Latency: {results['average_latency_ms']:.2f} ms")
    print(f"  Average Throughput: {results['average_throughput_bps']:.2f} bps")
    return results


def tests(dns_server='8.8.8.8'):
    print("\n" + "="*70)
    print("PART B: DNS Resolution Testing with Default Host Resolver")
    print("="*70)
    
    # Setup topology
    setLogLevel('info')
    topo = Topology()
    net = Mininet(topo=topo, link=TCLink, 
                  controller=lambda name: OVSController(name, ip='127.0.0.1', port=6633))
    
    try:
        net.start()
        
        info("\n*** Configuring NAT\n")
        nat = net.get('nat0')
        nat.configDefault()
        
        print("\nWaiting for network to stabilize...")
        time.sleep(3)
        
        print("\nTesting internal connectivity...")
        net.pingAll()
        
        time.sleep(2)
        
        print("\n*** Testing internet connectivity ***")
        h1 = net.get('h1')
        
        print("  Testing ping to 8.8.8.8...")
        result = h1.cmd('ping -c 3 -W 3 8.8.8.8')
        if 'bytes from 8.8.8.8' in result or '3 received' in result:
            print("  Internet connectivity working!")
        else:
            print(" Ping failed. Output:")
            print("  " + result.replace('\n', '\n  ')[:400])
        
        print(f"\nConfiguring DNS server ({dns_server}) for all hosts...")
        for host_name in ['h1', 'h2', 'h3', 'h4']:
            host = net.get(host_name)
            host.cmd(f'echo "nameserver {dns_server}" > /etc/resolv.conf')
            print(f"  {host_name}: DNS configured")
        
        print("\n*** Testing DNS resolution ***")
        test_result = h1.cmd('nslookup google.com ' + dns_server)
        if 'Address:' in test_result and 'google.com' in test_result.lower():
            print("  DNS resolution working!")
        else:
            print("   DNS test output:")
            print("  " + test_result.replace('\n', '\n  ')[:300])
        
        queries = {"h1": "queries_h1.txt", "h2": "queries_h2.txt", "h3": "queries_h3.txt", "h4": "queries_h4.txt"}
        
        all_results = []
        for host_name in ['h1', 'h2', 'h3', 'h4']:
            file = queries[host_name]
            results = test_dns_resolution(net, host_name, file, dns_server)
            all_results.append(results)
            time.sleep(1)  
        
        output_file = 'part_b_results.json'
        with open(output_file, 'w') as f:
            json.dump({
                'timestamp': datetime.now().isoformat(),
                'dns_server': dns_server,
                'results': all_results
            }, f, indent=2)
        
        print(f"\n{'='*70}")
        print(f"SUMMARY OF ALL HOSTS")
        print(f"{'='*70}")
        
        print(f"\n{'Host':<8} {'Total':<8} {'Success':<10} {'Failed':<8} {'Avg Latency':<15} {'Avg Throughput':<20}")
        print(f"{'-'*80}")
        for results in all_results:
            print(f"{results['host']:<8} {results['total_queries']:<8} "
                  f"{results['successful_queries']:<10} {results['failed_queries']:<8} "
                  f"{results['average_latency_ms']:<15.2f} {results['average_throughput_bps']:<20.2f}")
        
        print(f"\n{'='*70}")
        print(f"Results saved to: {output_file}")
        print(f"{'='*70}")
        
        
    except Exception as e:
        print(f"\nError during testing: {e}")
        import traceback
        traceback.print_exc()
    finally:
        print("\nStopping network...")
        net.stop()


if __name__ == '__main__':
    dns_server = '8.8.8.8'  
    
    if len(sys.argv) > 1:
        dns_server = sys.argv[1]
    
    print(f"Using DNS server: {dns_server}")
    tests(dns_server)
