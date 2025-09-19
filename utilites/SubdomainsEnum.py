import subprocess
import json
import argparse
from pathlib import Path
import socket


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
            if domain not in output:  # ensure uniqueness
                output[domain] = {"ip": None, "cname": None}
                if domain in massdns_data:
                    output[domain].update(massdns_data[domain])

                if output[domain]["ip"] is None and output[domain]["cname"]:
                    cname_target = output[domain]["cname"]
                    resolved_ip = dig_ip(cname_target)
                    if resolved_ip:
                        output[domain]["ip"] = resolved_ip
    return output


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("domain", help="Target domain")
    args = parser.parse_args()
    domain = args.domain

    base = Path("~/pieces").expanduser()
    output_dir = base / "output"
    data_dir = base / "data"
    output_dir.mkdir(parents=True, exist_ok=True)

    subfinder_file = output_dir / "subfinder.txt"
    live_file = output_dir / "live.txt"
    dns_file = output_dir / "dns.txt"
    resolvers_file = data_dir / "resolvers.txt"
    results_file = output_dir / "subdomains.json"

    subfinderCMD = [
        "subfinder", "-d", domain, "-silent", "-all", "-o", str(subfinder_file)
    ]
    subfinderProcess = subprocess.run(subfinderCMD, capture_output=True, text=True)
    if subfinderProcess.returncode != 0:
        print("Subfinder failed:", subfinderProcess.stderr)

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

    print(f"[+] Results saved to {results_file}")
