import os
import tempfile
import shutil
import urllib.parse
from src.merge_pcaps import *
from src.tshark_to_csv import *
from src.csv_to_neo4j import *

def pcap_workflow(pcap_files, mission_name, neo4j_url, neo4j_user, neo4j_password, neo4j_input_dir):
    try:
        with tempfile.TemporaryDirectory() as temp_dir:
            pcap_paths = []

            # Save uploaded PCAP files to temporary dir
            for i, file_obj in enumerate(pcap_files):
                if file_obj.name.endswith((".pcap", ".pcapng", ".cap", ".pcapppi")):
                    temp_path = os.path.join(temp_dir, f"{i}_{os.path.basename(file_obj.name)}")
                    shutil.copy(file_obj.name, temp_path)
                    pcap_paths.append(temp_path)

            if not pcap_paths:
                return "⚠️ No valid PCAP files provided."

            # Merge PCAPs
            merged_path = os.path.join(temp_dir, "merged.pcapng")
            merge_pcaps(pcap_paths, merged_path)

            # Run TShark to generate CSV
            raw_csv = os.path.join(temp_dir, mission_name + ".csv")
            run_tshark(merged_path, raw_csv, fields)
            decode_ssid_column(raw_csv)
            add_vendor_columns(raw_csv)

            #CSV to Neo4j
            neo4j_csv_path = os.path.join(neo4j_input_dir, mission_name + ".csv")
            shutil.copy(raw_csv, neo4j_csv_path)
            filename = urllib.parse.quote(os.path.basename(neo4j_csv_path))
            ingest_csv_into_neo4j(
                filename,
                neo4j_url,
                neo4j_user,
                neo4j_password,
                mission_name
            )

            return f"✅ Successfully ingested {len(pcap_paths)} PCAP{'s' if len(pcap_paths) > 1 else ''} for mission '{mission_name}'."

    except Exception as e:
        return f"❌ An error occurred during ingest:\n{str(e)}"