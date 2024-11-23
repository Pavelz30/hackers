import nmap
import ipaddress
import concurrent.futures


def expand_ip_range(ip_range):
    ip_range = ip_range.split(';')
    ip_list = []
    for ip in ip_range:
        parts = ip.split('-')
        base_ip = parts[0]
        base_parts = base_ip.split('.')

        start = int(base_parts[-1])
        end = int(parts[1]) if len(parts) > 1 else start

        for i in range(start, end + 1):
            ip_parts = base_parts[:-1] + [str(i)]
            ip_list.append('.'.join(ip_parts))
    
    return ip_list

def parse_cidr_to_ips(cidr):
    ip_range = cidr.split(';')
    ip_list = []
    for ip in ip_range:
        network = ipaddress.ip_network(ip)
        ip_list += [str(ip) for ip in network.hosts()]
    return ip_list



def scan_open_ports(target):
    nm = nmap.PortScanner()
    # nm.scan(target, arguments='-sT -sU -p 1-65000 -T5 -', sudo=True)
    nm.scan(target, arguments='-p 1-1000 -T5', sudo=True)
    open_ports = []
    for proto in nm[target].all_protocols():
        lport = nm[target][proto].keys()
        open_ports.extend(port for port in lport)

    print(f"Open ports on {target}: {open_ports}")
    return open_ports


def deep_service_scan(target, open_ports):
    nm = nmap.PortScanner()
    ports_str = ','.join(map(str, open_ports))
    nm.scan(target, ports_str, arguments=' -sV --script vulners', sudo=True)
    return nm

def process_ip(ip):
    print(ip)
    open_ports = scan_open_ports(ip)
    if open_ports:
        return deep_service_scan(ip, open_ports)
    else:
        print(f"No open ports found for {ip}, deep scan not required.")
        return None


def parallel_scan(expanded_ips):
    result_list = []
    
    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = {executor.submit(process_ip, ip): ip for ip in expanded_ips}
        
        for future in concurrent.futures.as_completed(futures):
            ip = futures[future]
            try:
                result = future.result()
                if result:
                    result_list.append(result)
            except Exception as exc:
                print(f"IP {ip} generated an exception: {exc}")

    return result_list


def main_scans(target_ip):
    if '-' in target_ip:
        expanded_ips = expand_ip_range(target_ip)
    elif '/' in target_ip:
        expanded_ips = parse_cidr_to_ips(target_ip)
    else:
        expanded_ips = target_ip.split(';')
    print("expanded_ips=", expanded_ips) 
    results_list = parallel_scan(expanded_ips)
    return results_list
    