from urllib.parse import urlparse
import subprocess, os
import xml.etree.ElementTree as ET
#Connect to Django
import os, django, subprocess
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "backend.api.settings")
django.setup()
from backend.core.models import *

def parse_nmap_xml(xml_file):
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()

        results = []

        for host in root.findall('host'):
            ports = host.find('ports')

            if ports is None:
                continue

            for port in ports.findall('port'):
                portid = port.get('portid')

                state_elem = port.find('state')
                state = state_elem.get('state') if state_elem is not None else "unknown"

                service_elem = port.find('service')
                if service_elem is not None:
                    service_name = service_elem.get('name', "unknown")
                    product = service_elem.get('product', "N/A")
                else:
                    service_name = "unknown"
                    product = "N/A"

                results.append({
                    "port": portid,
                    "state": state,
                    "service": service_name,
                    "product": product
                })

        return results

    except ET.ParseError as e:
        print(f"Error parsing XML: {e}")
        return []

def port_scan(url):
    parsed_url = urlparse(url)
    hostname = parsed_url.hostname

    out_dir = f'/work/backend/core/enum/output/{hostname}'
    out_file = f'/work/backend/core/enum/output/{hostname}/nmap.xml'
    os.makedirs(out_dir,exist_ok=True)

    print(f"[*] Starting nmap scan on {hostname}")
    cmd = ['nmap', '-sSV', hostname, '-oX', out_file]
    subprocess.run(cmd, text=True, capture_output=True)



    data = parse_nmap_xml(out_file)

    domain_obj = Subdomain.objects.get(hostname=hostname)

    for item in data:
        print(f"{item['port']} {item['state']} {item['service']} {item['product']}")
        Port.objects.update_or_create(
            subdomain=domain_obj,
            port_number=item['port'],
            defaults={
                'state': item['state'],
                'service_name': item['service'],
                'product_name': item['product']
            }
        )
    print(f"[+] Found {len(data)} ports on {hostname}")




