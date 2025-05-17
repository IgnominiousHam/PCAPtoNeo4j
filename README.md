# 📡 PCAP to Neo4j

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

- Python 3.7+
- [TShark](https://www.wireshark.org/docs/man-pages/tshark.html)
- [Neo4j Desktop](https://neo4j.com/download/) or local Neo4j instance
- The following Python packages (listed in `requirements.txt`):

```txt
neo4j
mac_vendor_lookup
tqdm
```

---

## 🚀 Getting Started
1. Clone the Repository
  ```txt
  git clone https://github.com/IgnominiousHam/PCAPtoNeo4j.git
  cd PCAPtoNeo4j
  ```
2. Create and Activate a Virtual Environment (Recommended)

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
    You'll need to run the script in the virtual environment so hang out here until your credentials are set.
   
4. Input Database Credentials

    In main.py, change the following lines: 
    ```txt
    neo4j_user = "neo4j" # Replace with your DB user
    neo4j_password = ""  # Replace with your DB password
    neo4j_input_dir = ""
    ```
    > In Neo4j Desktop, your input directory can be found by clicking the three dots next to "Open" > Open Folder > Import. 
    
    For Windows users, replace all "\\" in your path with "/"
   ```txt
    neo4j_input_dir = "C:/Users/User/.Neo4jDesktop/relate-data/dbmss/dbms-aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa/import"
   ```
5. Run
  ```txt
  python main.py
  ```

---

## 🧠 Recommended Use
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

---

## 🛠 Troubleshooting

- Make sure tshark is installed and available in your system’s PATH:
```txt
tshark -v
```
- Confirm that Neo4j is running and matches the URI in your main.py file.

- Ensure that dependencies are properly installed (see steps 2 and 3).

---
