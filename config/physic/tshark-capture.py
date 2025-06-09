#!/usr/bin/env python3

import os
import time
import subprocess
import re
from collections import Counter

COLLECTOR_DIR        = "{{ node_exporter_textfile_dir }}"
PROM_FILE_BASENAME   = "{{ promfile_basename }}"
PROM_FILE_PATH       = os.path.join(COLLECTOR_DIR, PROM_FILE_BASENAME)
CAPTURE_DURATION     = int({{ capture_duration }})
INTERFACE            = "{{ interface }}"

os.makedirs(COLLECTOR_DIR, exist_ok=True)
LOG_FILE = os.path.join(COLLECTOR_DIR, "tshark-capture.log")

{% raw %}
def log_error(msg):
    with open(LOG_FILE, "a") as f:
        f.write(msg + "\n")

def rotate_files():
    # Remove ONLY the old .prom.new file (never keep it)
    tmp_path = PROM_FILE_PATH + ".new"
    if os.path.exists(tmp_path):
        os.remove(tmp_path)

def capture_and_parse():
    try:
        pcap_file = "/tmp/phy_capture.pcap"
        if os.path.exists(pcap_file):
            os.remove(pcap_file)
        cmd_capture = [
            "tshark",
            "-i", INTERFACE,
            "-a", f"duration:{CAPTURE_DURATION}",
            "-w", pcap_file,
            "-F", "pcap"
        ]
        subprocess.run(cmd_capture, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        metrics = {}

        # 1. Real total number of packets and bytes (WHAOU!)
        cmd_count = [
            "tshark",
            "-r", pcap_file,
            "-T", "fields",
            "-e", "frame.len"
        ]
        pkt_count = 0
        byte_count = 0
        for line in subprocess.run(cmd_count, capture_output=True, text=True).stdout.splitlines():
            if line.strip().isdigit():
                pkt_count += 1
                byte_count += int(line.strip())
        metrics["phy_tshark_packets"] = pkt_count
        metrics["phy_tshark_bytes"]   = byte_count

        # 2. Per-protocol packet count
        cmd_proto = [
            "tshark",
            "-r", pcap_file,
            "-T", "fields",
            "-e", "_ws.col.Protocol"
        ]
        proto_output = subprocess.run(cmd_proto, capture_output=True, text=True).stdout
        proto_counts = Counter(proto_output.strip().splitlines())
        for proto, count in proto_counts.items():
            if proto:
                metrics[f'phy_tshark_proto_packets{{proto="{proto}"}}'] = count

        # 3. Top source IPs
        cmd_srcip = [
            "tshark",
            "-r", pcap_file,
            "-T", "fields",
            "-e", "ip.src"
        ]
        srcip_output = subprocess.run(cmd_srcip, capture_output=True, text=True).stdout
        srcip_counts = Counter(filter(None, srcip_output.strip().splitlines()))
        for ip, count in srcip_counts.most_common(5):
            metrics[f'phy_tshark_top_src{{ip="{ip}"}}'] = count

        # 4. Packet size distribution
        cmd_pktlen = [
            "tshark",
            "-r", pcap_file,
            "-T", "fields",
            "-e", "frame.len"
        ]
        pktlen_output = subprocess.run(cmd_pktlen, capture_output=True, text=True).stdout
        sizes = [int(x) for x in pktlen_output.strip().splitlines() if x.isdigit()]
        if sizes:
            metrics['phy_tshark_pkt_min'] = min(sizes)
            metrics['phy_tshark_pkt_max'] = max(sizes)
            metrics['phy_tshark_pkt_avg'] = sum(sizes) / len(sizes)
        else:
            metrics['phy_tshark_pkt_min'] = 0
            metrics['phy_tshark_pkt_max'] = 0
            metrics['phy_tshark_pkt_avg'] = 0

        # 5. ARP and ICMP, etc.
        for proto in ["ARP", "ICMP", "TCP", "UDP"]:
            metrics[f'phy_tshark_proto_packets{{proto="{proto}"}}'] = proto_counts.get(proto, 0)

        # 6. Error packets
        cmd_err = [
            "tshark",
            "-r", pcap_file,
            "-Y", "tcp.analysis.flags==1 || icmp.type==3"
        ]
        err_output = subprocess.run(cmd_err, capture_output=True, text=True).stdout
        metrics["phy_tshark_errors"] = len(err_output.strip().splitlines())

        # Atomic file write: write to .new then rename
        tmp_path = PROM_FILE_PATH + ".new"
        with open(tmp_path, "w") as f:
            f.write(f'# PHY metrics from tshark-capture.py\n')
            for k, v in metrics.items():
                if '{' in k and k.endswith('}'):
                    k = k[:-1] + f',iface="{INTERFACE}"' + '}'
                else:
                    k = f'{k}{{iface="{INTERFACE}"}}'
                f.write(f"{k} {v}\n")
        os.replace(tmp_path, PROM_FILE_PATH)

    except Exception as e:
        log_error(f'Error: {e}')
        # Also update prom file with error, using atomic replace
        tmp_path = PROM_FILE_PATH + ".new"
        with open(tmp_path, "w") as f:
            f.write(f'# error: {e}\n')
        os.replace(tmp_path, PROM_FILE_PATH)

def main():
    while True:
        rotate_files()
        capture_and_parse()
        time.sleep(1)

if __name__ == "__main__":
    main()
{% endraw %}