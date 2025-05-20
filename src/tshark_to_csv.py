import subprocess
import csv
import os
from mac_vendor_lookup import MacLookup

fields = [
    "ppi_gps.lat", "ppi_gps.lon", "wlan.fc.type_subtype",
    "wlan.sa", "wlan.da", "wlan.ssid", "wlan.bssid", "wlan.rsn.version", "wlan.fixed.capabilities.privacy", "wlan.wep.iv",
    "ip.src", "ip.dst", "ip.ttl",
    "tcp.srcport", "udp.srcport", "tcp.dstport", "udp.dstport",
    "http.user_agent", "dhcp.option.hostname", "dhcpv6.client_domain",
    "dns.ptr.domain_name", "dns.qry.name"
]

def is_hex_string(s):
    """Check if a string looks like hex (even length, all hex chars)."""
    try:
        return len(s) % 2 == 0 and all(c in "0123456789abcdefABCDEF" for c in s)
    except TypeError:
        return False

def decode_hex(s):
    """Convert hex to ASCII, or return original if not decodable."""
    if is_hex_string(s):
        try:
            return bytes.fromhex(s).decode('utf-8', errors='replace')
        except Exception:
            pass
    return s

def run_tshark(input_pcap, output_csv, fields):
    command = ["tshark", "-nr", input_pcap, "-T", "fields"]
    for field in fields:
        command += ["-e", field]
    command += [
        "-E", "header=y",
        "-E", "separator=,",
        "-E", "occurrence=f",
        "-E", "aggregator=,"
    ]

    with open(output_csv, "w", encoding="utf-8") as outfile:
        subprocess.run(command, stdout=outfile, check=True)

def decode_ssid_column(input_csv):
    """Decode wlan.ssid column in the CSV and write to new file."""
    output_csv = input_csv + ".tmp"

    with open(input_csv, "r", encoding="utf-8-sig") as infile, \
         open(output_csv, "w", newline='', encoding="utf-8") as outfile:

        reader = csv.DictReader(infile)
        if not reader.fieldnames or None in reader.fieldnames:
            raise ValueError("CSV header is malformed or contains invalid field names.")

        fieldnames = reader.fieldnames
        writer = csv.DictWriter(outfile, fieldnames=fieldnames)
        writer.writeheader()

        for row in reader:
            if None in row:
                continue

            if "wlan.ssid" in row and row["wlan.ssid"]:
                row["wlan.ssid"] = decode_hex(row["wlan.ssid"].strip())

            clean_row = {k: row.get(k, "") for k in fieldnames}
            writer.writerow(clean_row)

    os.replace(output_csv, input_csv)

def add_vendor_columns(csv_file):
    """Adds 'wlan.sa.vendor' and 'wlan.da.vendor' columns using mac-vendor-lookup."""
    mac_lookup = MacLookup()

    try:
        mac_lookup.update_vendors()
    except Exception as e:
        print(f"Vendor database update failed: {e}")
        pass
    temp_file = csv_file + ".tmp"

    with open(csv_file, "r", encoding="utf-8") as infile, \
         open(temp_file, "w", newline='', encoding="utf-8") as outfile:

        reader = csv.DictReader(infile)
        if not reader.fieldnames or None in reader.fieldnames:
            raise ValueError("CSV header is malformed or contains invalid field names.")

        new_fields = ["wlan.sa.vendor", "wlan.da.vendor"]
        fieldnames = reader.fieldnames + [f for f in new_fields if f not in reader.fieldnames]
        writer = csv.DictWriter(outfile, fieldnames=fieldnames)
        writer.writeheader()

        for row in reader:
            if None in row:
                continue

            sa_mac = row.get("wlan.sa", "").strip()
            try:
                row["wlan.sa.vendor"] = mac_lookup.lookup(sa_mac)
            except Exception:
                row["wlan.sa.vendor"] = ""

            da_mac = row.get("wlan.da", "").strip()
            try:
                row["wlan.da.vendor"] = mac_lookup.lookup(da_mac)
            except Exception:
                row["wlan.da.vendor"] = ""

            clean_row = {k: row.get(k, "") for k in fieldnames}
            writer.writerow(clean_row)

    os.replace(temp_file, csv_file)