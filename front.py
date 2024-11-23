from flask import Flask, render_template, request, jsonify
import nmap

app = Flask(__name__)

@app.route('/scan', methods=['POST'])
def scan():
    data = request.json
    ip_addresses = data.get('ips', '')
    scanner = nmap.PortScanner()
    
    results = {}
    
    # Выполнение сканирования
    scanner.scan(ip_addresses, '1-1024')
    
    for host in scanner.all_hosts():
        results[host] = {
            'state': scanner[host].state(),
            'protocols': scanner[host].all_protocols(),
            'ports': []
        }
        
        for proto in scanner[host].all_protocols():
            lport = scanner[host][proto].keys()
            for port in lport:
                results[host]['ports'].append({
                    'port': port,
                    'state': scanner[host][proto][port]['state']
                })
    
    return jsonify(results)
        
@app.route('/')
def index():
        return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)