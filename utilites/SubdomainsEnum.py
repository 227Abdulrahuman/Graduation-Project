import subprocess
import json
import argparse
from pathlib import Path
import socket

def extract_ips(json_file, output_file="ips.txt"):
    # Step 1: Load the JSON file
    with open(json_file, "r") as f:
        data = json.load(f)

    # Step 2: Extract IPs
    ips = []
    for domain, info in data.items():
        ip = info.get("ip")
        if ip:  # skip None/null
            ips.append(ip)

    # Step 3: Write IPs to file
    with open(output_file, "w") as f:
        for ip in ips:
            f.write(ip + "\n")

def parse_massdns(massdns_file):
    results = {}
    with open(massdns_file, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            parts = line.split()
            if len(parts) < 3:
                continue

            domain = parts[0].rstrip(".")
            record_type = parts[1]
            value = parts[2]

            if domain not in results:
                results[domain] = {"ip": None, "cname": None}

            if record_type == "A" and results[domain]["ip"] is None:
                results[domain]["ip"] = value
            elif record_type == "CNAME" and results[domain]["cname"] is None:
                results[domain]["cname"] = value.rstrip(".")
    return results

def dig_ip(hostname):
    try:
        return socket.gethostbyname(hostname)
    except Exception:
        return None

def build_json(live_file, massdns_data):
    output = {}
    with open(live_file, "r") as f:
        for line in f:
            domain = line.strip()
            if not domain:
                continue
            if domain not in output:
                output[domain] = {"ip": None, "cname": None}
                if domain in massdns_data:
                    output[domain].update(massdns_data[domain])

                if output[domain]["ip"] is None and output[domain]["cname"]:
                    cname_target = output[domain]["cname"]
                    resolved_ip = dig_ip(cname_target)
                    if resolved_ip:
                        output[domain]["ip"] = resolved_ip
    return output

def enrich_with_ports(json_file, ports_file, output_file="enriched.json"):
    with open(json_file, "r") as f:
        data = json.load(f)
    ip_ports = {}
    with open(ports_file, "r") as f:
        for line in f:
            line = line.strip()
            if not line or ":" not in line:
                continue
            ip, port = line.split(":")
            ip_ports.setdefault(ip, set()).add(int(port))
    for domain, info in data.items():
        ip = info.get("ip")
        if ip and ip in ip_ports:
            info["ports"] = sorted(ip_ports[ip])
        else:
            info["ports"] = []
    with open(output_file, "w") as f:
        json.dump(data, f, indent=4)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("domain", help="Target domain")
    args = parser.parse_args()
    domain = args.domain

    base = Path("../pieces")
    output_dir = base / "output"
    data_dir = base / "data"
    temp_dir = base / "tmp"
    output_dir.mkdir(parents=True, exist_ok=True)

    subfinder_file = temp_dir / "subfinder.txt"
    live_file = temp_dir / "live.txt"
    dns_file = temp_dir / "dns.txt"
    ips_file = temp_dir / "ips.txt"
    port_file = temp_dir / "ports.txt"
    results_file = temp_dir / f"SUBS_{domain}.json"

    resolvers_file = data_dir / "resolvers.txt"

    final_file = output_dir / f"SUBS_{domain}.json"

    subfinderCMD = [
        "subfinder", "-d", domain, "-silent", "-all", "-o", str(subfinder_file)
    ]
    subfinderCMD = subprocess.run(subfinderCMD, capture_output=True, text=True)
    if subfinderCMD.returncode != 0:
        print("Subfinder failed:", subfinderCMD.stderr)

    purednsCMD = [
        "puredns", "resolve", str(subfinder_file),
        "-w", str(live_file),
        "-r", str(resolvers_file),
        "--write-massdns", str(dns_file)
    ]
    purednsProcess = subprocess.run(purednsCMD, capture_output=True, text=True)
    if purednsProcess.returncode != 0:
        print("PureDNS failed:", purednsProcess.stderr)

    massdns_data = parse_massdns(dns_file)
    result = build_json(live_file, massdns_data)

    with open(results_file, "w") as f:
        json.dump(result, f, indent=4)

    extract_ips(results_file,str(ips_file))

    naabuCMD = [
        "naabu", "-list", str(ips_file),
        "-Pn",
        "-o", str(port_file)
    ]
    naabuProcess = subprocess.run(naabuCMD, capture_output=True, text=True)
    if naabuProcess.returncode != 0:
        print("naabu failed:", naabuProcess.stderr)


    enrich_with_ports(results_file,port_file,str(final_file))

    print(f"[+] Results saved to {final_file}")
