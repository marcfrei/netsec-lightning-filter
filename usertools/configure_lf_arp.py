#! /usr/bin/env python3

import subprocess
import sys
import json


def arp_request(ip: str):
    success = False
    mac = None
    for _ in range(7):
        if success:
            break
        result = subprocess.run(
            ["arping", "-i", "virtio_user0", ip, "-w", "5"], capture_output=True, text=True
        )

        if "60 bytes from " in result.stdout:
            success = True
            s = result.stdout.index('60 bytes from ')
            mac = result.stdout[s+14:s+31]
            print(f"MAC for {ip}:", mac)
            break
    return mac



# load LF config to extract relevant addresses
old_config_path = sys.argv[1] 
new_config_path = sys.argv[2]
outbound_ip = sys.argv[3]

with open(old_config_path, "r") as f:
    config = json.load(f)

inbound_ip = config["inbound"]["scion_dst"]


# make arp requests if needed
if config["inbound"]["ether"] == "00:00:00:00:00:00":
    mac = arp_request(inbound_ip)
    if mac != None:
        config["inbound"]["ether"] = mac

if config["outbound"]["ether"] == "00:00:00:00:00:00":
    mac = arp_request(outbound_ip)
    if mac != None:
        config["outbound"]["ether"] = mac


# write new config
with open(new_config_path, "w") as f:
    json.dump(config, f)
