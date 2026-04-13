import os
import json
import subprocess
from backend.core.models import *

def scan_ports(domain_name):

    input_file = f"/work/output/{domain_name}/live_subdomains.txt"
    output_file = f"/work/output/{domain_name}/ports.json"

    target_ports = "8080,8443,8888,9200,9300,27017,6379,5601,2375,2376,10250,4848,8161,9090,3000,5000,11211"

    command = [
        "naabu",
        "-l", input_file,
        "-p", target_ports,
        "-j",
        "-o", output_file
    ]

    service_map = {
        8080: "Alt HTTP/HTTPS",
        8443: "Alt HTTP/HTTPS",
        8888: "Alt HTTP/HTTPS",
        9200: "Elasticsearch",
        9300: "Elasticsearch",
        27017: "MongoDB",
        6379: "Redis",
        5601: "Kibana",
        2375: "Docker API",
        2376: "Docker API",
        10250: "Kubernetes API (kubelet)",
        4848: "GlassFish admin",
        8161: "ActiveMQ",
        9090: "Prometheus/Cockpit",
        3000: "Grafana, dev apps",
        5000: "Flask dev server, Docker registry",
        11211: "Memcached"
    }

    print(f"[*] Starting Port scan for {domain_name}...")
    try:
        subprocess.run(command, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError as e:
        print(f"[-] Port scan failed: {e}")
        return
    except FileNotFoundError:
        print("[-] Port executable not found. Please ensure it is installed and in your system PATH.")
        return

    if not os.path.exists(output_file):
        print(f"[-] Output file {output_file} not found. Scan may have found no open ports.")
        return

    with open(output_file, 'r') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            try:
                data = json.loads(line)
                host = data.get("host")
                ip = data.get("ip")
                port_num = data.get("port")

                if not host or not port_num:
                    continue

                subdomain = Subdomain.objects.filter(hostname=host).first()

                if subdomain:
                    if not subdomain.ip and ip:
                        subdomain.ip = ip
                        subdomain.save(update_fields=['ip'])

                    service_name = service_map.get(port_num, "Unknown")

                    Port.objects.get_or_create(
                        subdomain=subdomain,
                        number=port_num,
                        defaults={'service': service_name}
                    )

            except json.JSONDecodeError:
                print(f"[-] Failed to parse JSON line: {line}")
            except Exception as e:
                print(f"[-] Error processing entry {line}: {str(e)}")

    print("[+] Port scan completed successfully.")
