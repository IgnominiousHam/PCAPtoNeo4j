from neo4j import GraphDatabase
from tqdm import tqdm

def ingest_csv_into_neo4j(filename, neo4j_url, neo4j_user, neo4j_password, mission_name):
    try:
        driver = GraphDatabase.driver(neo4j_url, auth=(neo4j_user, neo4j_password))

        index_queries = [
            "CREATE INDEX IF NOT EXISTS FOR (a:IP) ON (a.address)",    
            "CREATE INDEX IF NOT EXISTS FOR (a:MAC) ON (a.address)",   
            "CREATE INDEX IF NOT EXISTS FOR (a:Security) ON (a.security)",      
            "CREATE INDEX IF NOT EXISTS FOR (a:PORT) ON (a.number)",       
            "CREATE INDEX IF NOT EXISTS FOR (a:SSID) ON (a.name)",          
            "CREATE INDEX IF NOT EXISTS FOR (a:Hostname) ON (a.hostname)",  
            "CREATE INDEX IF NOT EXISTS FOR (a:DNSQuery) ON (a.query)",      
            "CREATE INDEX IF NOT EXISTS FOR (a:UserAgent) ON (a.agent)",     
            "CREATE INDEX IF NOT EXISTS FOR (a:TTL) ON (a.hops)",           
            "CREATE INDEX IF NOT EXISTS FOR (a:Mission) ON (a.mission)",
            "CREATE INDEX IF NOT EXISTS FOR (a:Vendor) ON (a.name)"  

        ]

        queries = [

            #MISSION
            f"""
            MERGE (m:Mission {{mission: '{mission_name}'}})
            """,

            #MAC INITIAL MERGE
            f"""
            LOAD CSV WITH HEADERS FROM 'file:///{filename}' AS row
            WITH row WHERE NOT row.`wlan.sa` CONTAINS ','
            MATCH (m:Mission {{mission: '{mission_name}'}})
            MERGE (b:MAC {{address: row.`wlan.sa`}})
            MERGE (b)-[:OBSERVED_IN]->(m)
            """,

            f"""
            LOAD CSV WITH HEADERS FROM 'file:///{filename}' AS row
            WITH row WHERE row.`wlan.da` <> "ff:ff:ff:ff:ff:ff" 
            MERGE (b:MAC {{address: row.`wlan.da`}})
            MERGE (b)-[:OBSERVED_IN]->(m)
            """,

            #OUI LOOKUP
            f"""
            LOAD CSV WITH HEADERS FROM 'file:///{filename}' AS row
            WITH row WHERE row.`wlan.sa.vendor` <> "" 
            MATCH (b:MAC {{address: row.`wlan.sa`}})
            MERGE (m: Vendor {{name: row.`wlan.sa.vendor`}})
            MERGE (b)-[:HAS_VENDOR]->(m)
            """,

            f"""
            LOAD CSV WITH HEADERS FROM 'file:///{filename}' AS row
            WITH row WHERE row.`wlan.da.vendor` <> "" 
            MATCH (b:MAC {{address: row.`wlan.da`}})
            MERGE (m: Vendor {{name: row.`wlan.da.vendor`}})
            MERGE (b)-[:HAS_VENDOR]->(m)
            """,

            #GEOLOCATION
            f"""
            LOAD CSV WITH HEADERS FROM 'file:///{filename}' AS row
            WITH row 
            WHERE row.`ppi_gps.lat` <> '' AND row.`ppi_gps.lon` <> ''
            MERGE (p:Location {{location: point({{latitude: toFloat(row.`ppi_gps.lat`), longitude: toFloat(row.`ppi_gps.lon`)}})}})
            """,

            f"""
            LOAD CSV WITH HEADERS FROM 'file:///{filename}' AS row
            WITH row 
            WHERE row.`ppi_gps.lat` <> '' AND row.`ppi_gps.lon` <> ''
            MATCH (p:Location {{location: point({{latitude: toFloat(row.`ppi_gps.lat`), longitude: toFloat(row.`ppi_gps.lon`)}})}})
            MATCH (b:MAC {{address: row.`wlan.sa`}})
            MERGE (b)-[:SEEN_AT]->(p)
            """,

            #SECURITY
            f"""
            LOAD CSV WITH HEADERS FROM 'file:///{filename}' AS row
            WITH row WHERE row.`wlan.fc.type_subtype` = '0x0008' AND row.`wlan.fixed.capabilities.privacy` = 'False'
            MATCH (m1: MAC {{address: row.`wlan.sa`}})
            MERGE (e:Security {{security: 'OPEN'}})
            MERGE (m1)-[:HAS_SECURITY]->(e)
            """,

            f"""
            LOAD CSV WITH HEADERS FROM 'file:///{filename}' AS row
            WITH row WHERE row.`wlan.fc.type_subtype` = '0x0008' AND row.`wlan.fixed.capabilities.privacy` = 'True' AND row.`wlan.rsn.version` = '1'
            MATCH (m1: MAC {{address: row.`wlan.sa`}})
            MERGE (e:Security {{security: 'WPA/WPA2'}})
            MERGE (m1)-[:HAS_SECURITY]->(e)
            """,

            f"""
            LOAD CSV WITH HEADERS FROM 'file:///{filename}' AS row
            WITH row WHERE row.`wlan.bssid` <> '' AND row.`wlan.wep.iv` <> ''
            MATCH (m1: MAC {{address: row.`wlan.bssid`}})
            MERGE (e:Security {{security: 'WEP'}})
            MERGE (m1)-[:HAS_SECURITY]->(e)
            """,
      
            #ACTUAL DEVICE-TO-DEVICE COMMUNICATION
            f"""
            LOAD CSV WITH HEADERS FROM 'file:///{filename}' AS row
            WITH row WHERE row.`wlan.fc.type_subtype` <> '0x0005' AND NOT row.`wlan.da` STARTS WITH '01:' AND NOT row.`wlan.da` STARTS WITH '33:33:'
            MATCH (m1: MAC {{address: row.`wlan.sa`}})
            MATCH (m2: MAC {{address: row.`wlan.da`}})
            MERGE (m1)-[:COMMUNICATES_WITH]->(m2)
            """,

            #MULTICAST STUFF
            f"""
            LOAD CSV WITH HEADERS FROM 'file:///{filename}' AS row
            WITH row WHERE row.`wlan.da` STARTS WITH '01:' OR row.`wlan.da` STARTS WITH '33:33:'
            MATCH (m1: MAC {{address: row.`wlan.sa`}})
            MATCH (m2: MAC {{address: row.`wlan.da`}})
            MERGE (m1)-[:MULTICASTS_TO]->(m2)
            """, 

            #MAC-TO-SSID
            f"""
            LOAD CSV WITH HEADERS FROM 'file:///{filename}' AS row
            WITH row WHERE row.`wlan.fc.type_subtype` = '0x0008' AND row.`wlan.ssid` <> '<MISSING>'
            MATCH (b:MAC {{address: row.`wlan.sa`}})
            MERGE (s:SSID {{name: row.`wlan.ssid`}})
            MERGE (b)-[:BROADCASTS]->(s)
            """,

            #DIRECTED PROBES
            f"""
            LOAD CSV WITH HEADERS FROM 'file:///{filename}' AS row
            WITH row WHERE row.`wlan.fc.type_subtype` = '0x0004' AND row.`wlan.ssid` <> '<MISSING>'
            MATCH (b:MAC {{address: row.`wlan.sa`}})
            MERGE (s:SSID {{name: row.`wlan.ssid`}})
            MERGE (b)-[:DIRECTED_PROBES_FOR]->(s)
            """,

            #PROBE RESPONSES
            f"""
            LOAD CSV WITH HEADERS FROM 'file:///{filename}' AS row
            WITH row WHERE row.`wlan.fc.type_subtype` = '0x0005'
            MATCH (b:MAC {{address: row.`wlan.sa`}})
            MATCH (s:MAC {{address: row.`wlan.da`}})
            MERGE (b)-[:PROBE_RESPONSE_TO]->(s)           
            """,

            #MAC TO PRIVATE IP CORRELATION
            f"""
            LOAD CSV WITH HEADERS FROM 'file:///{filename}' AS row
            WITH row
            WHERE 
                (row.`ip.src` STARTS WITH '10.' OR 
                row.`ip.src` STARTS WITH '172.' AND toInteger(split(row.`ip.src`, '.')[1]) >= 16 AND toInteger(split(row.`ip.src`, '.')[1]) <= 31 OR 
                row.`ip.src` STARTS WITH '192.' AND toInteger(split(row.`ip.src`, '.')[1]) = 168  
                AND NOT row.`ip.src` CONTAINS ',' AND NOT row.`ip.dst` CONTAINS ','
                AND NOT row.`ip.src` ENDS WITH '250' AND NOT row.`ip.dst` ENDS WITH '250'
                AND row.`wlan.sa` <> 'ff:ff:ff:ff:ff:ff') AND row.`wlan.da` <> 'ff:ff:ff:ff:ff:ff'
            MATCH (m1:MAC {{address: row.`wlan.sa`}}) 
            MERGE (i1:IP {{address: row.`ip.src`}})
            MERGE (m1)-[:ASSOCIATED_WITH]->(i1)
            """,

            f"""
            LOAD CSV WITH HEADERS FROM 'file:///{filename}' AS row
            WITH row
            WHERE 
                (row.`ip.dst` STARTS WITH '10.' OR 
                row.`ip.dst` STARTS WITH '172.' AND toInteger(split(row.`ip.dst`, '.')[1]) >= 16 AND toInteger(split(row.`ip.dst`, '.')[1]) <= 31 OR 
                row.`ip.dst` STARTS WITH '192.' AND toInteger(split(row.`ip.dst`, '.')[1]) = 168
                AND NOT row.`ip.src` CONTAINS ',' AND NOT row.`ip.dst` CONTAINS ','
                AND NOT row.`ip.src` ENDS WITH '250' AND NOT row.`ip.dst` ENDS WITH '250'
                AND row.`wlan.da` <> 'ff:ff:ff:ff:ff:ff' AND row.`wlan.sa` <> 'ff:ff:ff:ff:ff:ff'
                )
            MATCH (m2:MAC {{address: row.`wlan.da`}}) 
            MERGE (i2:IP {{address: row.`ip.dst`}}) 
            MERGE (m2)-[:ASSOCIATED_WITH]->(i2)
            """,

            #PUBLIC IP HANDLING
            f"""
            LOAD CSV WITH HEADERS FROM 'file:///{filename}' AS row
            WITH row WHERE row.`ip.src` IS NOT NULL AND NOT row.`ip.src` CONTAINS ','
            MERGE (i:IP {{address: row.`ip.src`}})
            """,
  
            f"""
            LOAD CSV WITH HEADERS FROM 'file:///{filename}' AS row
            WITH row WHERE row.`ip.dst` IS NOT NULL AND NOT row.`ip.dst` CONTAINS ','
            MERGE (i:IP {{address: row.`ip.dst`}})
            """,

            #IP-TO-IP
            f"""
            LOAD CSV WITH HEADERS FROM 'file:///{filename}' AS row 
            WITH row
            MATCH (i1: IP {{address: row.`ip.src`}})
            MATCH (i2: IP {{address: row.`ip.dst`}})
            MERGE (i1)-[:COMMUNICATES_WITH]->(i2)
            """,

            #PORTS
            f"""
            LOAD CSV WITH HEADERS FROM 'file:///{filename}' AS row
            WITH row
            WHERE NOT (toInteger(row.`tcp.dstport`) >= 49152 AND toInteger(row.`tcp.dstport`) <= 65535) 
            MERGE (p1:PORT {{number: row.`tcp.dstport`}})
            """,

            f"""
            LOAD CSV WITH HEADERS FROM 'file:///{filename}' AS row
            WITH row
            WHERE NOT (toInteger(row.`udp.dstport`) >= 49152 AND toInteger(row.`udp.dstport`) <= 65535) 
            MERGE (p1:PORT {{number: row.`udp.dstport`}})
            """,

  
            f"""
            LOAD CSV WITH HEADERS FROM 'file:///{filename}' AS row
            WITH row
            WHERE NOT (toInteger(row.`tcp.srcport`) >= 49152 AND toInteger(row.`tcp.srcport`) <= 65535) 
            MERGE (p1:PORT {{number: row.`tcp.srcport`}})
            """,

            f"""
            LOAD CSV WITH HEADERS FROM 'file:///{filename}' AS row
            WITH row
            WHERE NOT (toInteger(row.`udp.srcport`) >= 49152 AND toInteger(row.`udp.srcport`) <= 65535) 
            MERGE (p1:PORT {{number: row.`udp.srcport`}})
            """,

            f"""
            LOAD CSV WITH HEADERS FROM 'file:///{filename}' AS row
            WITH row
            MATCH (i:IP {{address: row.`ip.src`}})
            MATCH (p:PORT {{number: row.`tcp.srcport`}})
            MERGE (i)-[:HAS_OPEN_PORT]->(p)
            """,

            f"""
            LOAD CSV WITH HEADERS FROM 'file:///{filename}' AS row
            WITH row
            MATCH (i:IP {{address: row.`ip.src`}})
            MATCH (p:PORT {{number: row.`udp.srcport`}})
            MERGE (i)-[:HAS_OPEN_PORT]->(p)
            """, 

            f"""
            LOAD CSV WITH HEADERS FROM 'file:///{filename}' AS row
            WITH row
            MATCH (i:IP {{address: row.`ip.dst`}})
            MATCH (p:PORT {{number: row.`tcp.dstport`}})
            MERGE (i)-[:HAS_OPEN_PORT]->(p)           
            """,

            f"""
            LOAD CSV WITH HEADERS FROM 'file:///{filename}' AS row
            WITH row
            MATCH (i:IP {{address: row.`ip.dst`}})
            MATCH (p:PORT {{number: row.`udp.dstport`}})
            MERGE (i)-[:HAS_OPEN_PORT]->(p)           
            """,

            #MAC TO USER AGENT STRING CORRELATION
            f"""
            LOAD CSV WITH HEADERS FROM 'file:///{filename}' AS row 
            WITH row WHERE row.`http.user_agent` <> ''
            MATCH (i1:MAC {{address: row.`wlan.sa`}})
            MERGE (ua: UserAgent {{agent: row.`http.user_agent`}})
            MERGE (i1)-[:HAS_USER_AGENT]->(ua)
            """,

            #MACT TO HOSTNAME CORRELATION
            f"""
            LOAD CSV WITH HEADERS FROM 'file:///{filename}' AS row 
            WITH row WHERE row.`dhcp.option.hostname` <> ''
            MATCH (i1:MAC {{address: row.`wlan.sa`}})
            MERGE (hn: Hostname {{hostname: row.`dhcp.option.hostname`}})
            MERGE (i1)-[:HAS_HOSTNAME]->(hn)
            """,

            f"""
            LOAD CSV WITH HEADERS FROM 'file:///{filename}' AS row 
            WITH row WHERE row.`dhcpv6.client_domain` <> ''
            MATCH (i1:MAC {{address: row.`wlan.sa`}})
            MERGE (hn: Hostname {{hostname: row.`dhcpv6.client_domain`}})
            MERGE (i1)-[:HAS_HOSTNAME]->(hn)
            """,

            f"""
            LOAD CSV WITH HEADERS FROM 'file:///{filename}' AS row 
            WITH row WHERE row.`dns.ptr.domain_name` <> ''
            MATCH (i1:MAC {{address: row.`wlan.sa`}})
            MERGE (hn: Hostname {{hostname: row.`dns.ptr.domain_name`}})
            MERGE (i1)-[:HAS_HOSTNAME]->(hn)
            """,

            #MATCHING IP TO DNS QUERIES
            f"""
            LOAD CSV WITH HEADERS FROM 'file:///{filename}' AS row 
            WITH row WHERE row.`dns.qry.name` <> '' AND row.`ip.src` IS NOT NULL
            MATCH (i1:IP {{address: row.`ip.src`}})
            MERGE (dq: DNSQuery {{query: row.`dns.qry.name`}})
            MERGE (i1)-[:QUERIED_FOR]->(dq)
            """,

            #MAC TO TIME-TO-LIVE
            f"""
            LOAD CSV WITH HEADERS FROM 'file:///{filename}' AS row
            WITH row WHERE (row.`ip.ttl` = "64" OR row.`ip.ttl` = "128") AND row.`ip.src` <> "0.0.0.0"
            MATCH (i1:MAC {{address: row.`wlan.sa`}})
            MERGE (ttl:TTL {{hops: row.`ip.ttl`}})
            MERGE (i1)-[:HAS_TTL]->(ttl)
            """

        ]
        
        with driver.session() as session:
            for query in index_queries:
                session.run(query)
            for query in tqdm(queries, desc=f"Importing {filename}", unit="file"):
                session.run(query)
                
        
    except Exception as e:
        print(f"Error occurred while ingesting data into Neo4j: {e}")
    finally:
        driver.close()

