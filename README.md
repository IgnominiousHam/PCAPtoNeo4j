# 🐬 PCAP to Neo4j

Some python that parses wifi packet capture (`.pcap`) files using **TShark**, extracts network metadata, and ingests the data into a local **Neo4j** graph database.

---

## 🔧 Features

- Parses `.pcap` files via `tshark` (Wireshark CLI)
- Extracts network connections and metadata
- Builds nodes and relationships in **Neo4j**
- Tracks IPs, MACs, ports, and more
- MAC vendor lookup

---

## 📦 Requirements

- [Neo4j Desktop](https://neo4j.com/download/) or local Neo4j instance

If building from source:
- Python 3.7+
- [TShark](https://www.wireshark.org/docs/man-pages/tshark.html)

---

## 🚀 Getting Started

Option 1 (Recommended): Download from releases, then run pcap_to_neo4j.exe.

Option 2: Build from source: 
1. Clone the Repository
  ```txt
  git clone https://github.com/IgnominiousHam/PCAPtoNeo4j.git
  cd PCAPtoNeo4j
  ```
2. Create and Activate a Virtual Environment

    Create and activate .venv:
    On Windows:
    ```txt
    python -m venv .venv
    .venv\Scripts\activate
    ```
    On macOS/Linux:
    ```txt
    python3 -m venv .venv
    source .venv/bin/activate
    ```
    Once activated, your terminal prompt should show the .venv environment.

3. Install Dependencies

    With the virtual environment activated:
      ```txt
      pip install -r requirements.txt
      ```
   
4. Run

   Ensure that you're in the PCAPtoNeo4j directory and your virtual environment is still active, then enter the following:
    ```txt
    python app.py
    ```

---

## 🛠 Using the Web UI
 - Ensure that Neo4j database is started in the Neo4j Desktop app.
 - If you don't know your credentials/haven't made a database, head into Neo4j Desktop and click Add > Local DBMS.
 - Once your database has been started, you can check your import directory using the three dots in the top right, then Open Folder > Import. Paste the full file path into the field.
 - Select desired pcaps to ingest.
 - Name your mission. If importing pcaps for the same event, make sure you keep this consistent. Mission is designed as a way to correlate devices seen in multiple locations if you don't have GPS, so try to name it something intuitive (like place_date).
 - Ingest takes a while, so be patient. If it works, you'll see a "✅ Successfully ingested..." message in the output section.

---

## 🧠 Recommended Queries
In Neo4j Desktop, open Graph Apps, then choose **Neo4j Bloom**. This will let you perform dynamic queries without writing cypher, which is very nice because cypher can be pretty annoying.

For viewing geolocations, you'll need to use **NeoDash**. Here are some snazzy queries for displaying map data:

View device location:
```txt
MATCH (b:MAC {address:your_mac_address})-[:SEEN_AT]->(a:Location)
RETURN a
 ```
View access points in a bounding box:
```txt
MATCH (b:MAC)-[:SEEN_AT]->(a:Location)
MATCH (b:MAC)-[:BROADCASTS]->(d:SSID)
WHERE point.withinBBox(
  a.location,
  point({latitude:toFloat(bottom_left_latitude), longitude:toFloat(bottom_left_longitude)}), 
  point({latitude:toFloat(top_right_latitude), longitude:toFloat(top_right_longitude)}))
RETURN b.address,d.name
```
View manufacturers of devices in a bounding box:
```txt
MATCH (b:MAC)-[:SEEN_AT]->(a:Location)
MATCH (b)-[:HAS_VENDOR]->(d:Vendor)
WHERE point.withinBBox(
  a.location,
  point({latitude:toFloat(bottom_left_latitude), longitude:toFloat(bottom_left_longitude)}), 
  point({latitude:toFloat(top_right_latitude), longitude:toFloat(top_right_longitude)}))
RETURN d.name AS vendor, count(*) AS mac_count
```

