import nmap


def expand_ip_range(ip_range):
    
    parts = ip_range.split('-')
    base_ip = parts[0]
    base_parts = base_ip.split('.')

    start = int(base_parts[-1])
    end = int(parts[1]) if len(parts) > 1 else start

    ip_list = []
    for i in range(start, end + 1):
        ip_parts = base_parts[:-1] + [str(i)]
        ip_list.append('.'.join(ip_parts))
    
    return ip_list


def scan_open_ports(target):
    nm = nmap.PortScanner()
    # nm.scan(target, arguments='-sT -sU -p 1-65000 -T5 --min-rate 1000', sudo=True)
    nm.scan(target, arguments='-p 1-1000 -T5 --min-rate 1000', sudo=True)
    open_ports = []
    expanded_ips = expand_ip_range(target)
    print(expanded_ips)
    for ips in expanded_ips:
        for proto in nm[ips].all_protocols():
            lport = nm[ips][proto].keys()
            open_ports.extend(port for port in lport)

    print(f"Open ports on {target}: {open_ports}")
    return open_ports


def deep_service_scan(target, open_ports):
    nm = nmap.PortScanner()
    ports_str = ','.join(map(str, open_ports))
    nm.scan(target, ports_str, arguments='-sV', sudo=True)
    return nm


def main_scans(target_ip):
    expanded_ips = expand_ip_range(target_ip)
    result_list = []
    print(expanded_ips)
    for ip in expanded_ips:
        open_ports = scan_open_ports(ip)
        if open_ports:
            result_list.append(deep_service_scan(ip, open_ports))
        else:
            print("No open ports found, deep scan not required.")
    return result_list
    