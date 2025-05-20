import os
import subprocess

def find_pcap_files(root_dir, extensions=('.pcap', '.pcapng', '.cap', '.pcapppi')):
    """Recursively find all pcap/pcapng files under root_dir."""
    pcap_files = []
    for dirpath, _, filenames in os.walk(root_dir):
        for file in filenames:
            if file.lower().endswith(extensions):
                pcap_files.append(os.path.join(dirpath, file))
    return pcap_files

def merge_pcaps(pcap_files, output_file):
    """Use mergecap to merge given PCAP files into one output file."""
    if not pcap_files:
        print("No PCAP files found.")
        return

    command = ['mergecap', '-w', output_file] + pcap_files
    subprocess.run(command, check=True)

