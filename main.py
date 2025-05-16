import os, shutil
from merge_pcaps import *
from tshark_to_csv import *
from csv_to_neo4j import *

#Configuration Options
neo4j_url = "bolt://localhost:7687"
neo4j_user = "neo4j" # Replace with your DB user
neo4j_password = ""  # Replace with your DB password
neo4j_input_dir = "" #Replace with DB import directory (drop down on neo4j home page)



if __name__ == "__main__":

    # Merge PCAPs
    current_directory = input("PCAP directory: ").strip('"')
    output_pcap = os.path.join(current_directory, "merged.pcapng")
    all_pcaps = find_pcap_files(current_directory)
    merge_pcaps(all_pcaps, output_pcap)

    # TShark to CSV
    mission_name = input("Mission filename: ")
    raw_csv = os.path.join(current_directory, mission_name + ".csv")
    run_tshark(output_pcap, raw_csv, fields)
    decode_ssid_column(raw_csv)
    add_vendor_columns(raw_csv)
    neo4j_filepath = os.path.join(neo4j_input_dir, mission_name + ".csv")
    shutil.copy(raw_csv, neo4j_filepath)

    # Ingest into Neo4j
    filename = mission_name + ".csv"
    ingest_csv_into_neo4j(filename, neo4j_url, neo4j_user, neo4j_password, mission_name)

    if os.path.exists(output_pcap):
        os.remove(output_pcap)
    if os.path.exists(raw_csv):
        os.remove(raw_csv)

    print("CSV data successfully ingested into Neo4j.")