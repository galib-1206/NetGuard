import scapy.all as scapy
import pandas as pd

import shutil



# Create an empty DataFrame to store the data
df = pd.DataFrame(columns=[
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
    'land', 'wrong_fragment', 'urgent', 'packet_payload_len', 'src_ip_len',
    'dst_ip_len', 'src_port_num', 'dst_port_num', 'icmp_type_code', 'icmp_code_code'
])


def parse_packet(packet):
    if packet.haslayer(scapy.IP):
        if packet.haslayer(scapy.TCP):
            src_port = packet[scapy.TCP].sport
            dst_port = packet[scapy.TCP].dport
            protocol = "tcp"
            tcp_flags = packet[scapy.TCP].flags
            icmp_type = None
            icmp_code = None
        elif packet.haslayer(scapy.UDP):
            src_port = packet[scapy.UDP].sport
            dst_port = packet[scapy.UDP].dport
            protocol = "udp"
            tcp_flags = None
            icmp_type = None
            icmp_code = None
        elif packet.haslayer(scapy.ICMP):
            src_port = None
            dst_port = None
            protocol = "icmp"
            tcp_flags = None
            icmp_type = packet[scapy.ICMP].type
            icmp_code = packet[scapy.ICMP].code
        else:
            src_port = None
            dst_port = None
            protocol = "unknown"
            tcp_flags = None
            icmp_type = None
            icmp_code = None

        # Extract source and destination IP addresses
        src_ip = packet[scapy.IP].src
        dst_ip = packet[scapy.IP].dst

        # Extract packet length and timestamp
        packet_len = packet.len
        timestamp = packet.time

        # Extract packet payload
        packet_payload = packet[scapy.IP].payload

        return {
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': src_port,
            'dst_port': dst_port,
            'protocol': protocol,
            'packet_len': packet_len,
            'timestamp': timestamp,
            'tcp_flags': tcp_flags,
            'icmp_type': icmp_type,
            'icmp_code': icmp_code,
            'packet_payload': packet_payload
        }
    else:
        # Handle packets that do not have an IP layer
        return None


port_to_service_map = {
    20: 'ftp_data',
    21: 'ftp',
    22: 'ssh',
    23: 'telnet',
    25: 'smtp',
    37: 'time',
    42: 'name',
    43: 'whois',
    53: 'domain',
    67: 'tftp_u',
    69: 'tftp_u',
    70: 'gopher',
    79: 'finger',
    80: 'http',
    110: 'pop_3',
    111: 'sunrpc',
    113: 'auth',
    115: 'sftp',
    119: 'nntp',
    123: 'ntp_u',
    135: 'netbios_ns',
    137: 'netbios_ns',
    138: 'netbios_dgm',
    139: 'netbios_ssn',
    143: 'imap4',
    179: 'bgp',
    443: 'http_443',
    445: 'microsoft_ds',
    513: 'login',
    514: 'shell',
    515: 'printer',
    520: 'rje',
    540: 'uucp',
    554: 'rtsp',
    636: 'ldap',
    873: 'rsync',
    993: 'imap4',
    995: 'pop_3',
    1080: 'socks',
    1433: 'sql_net',
    1434: 'sql_net',
    1521: 'sql_net',
    2049: 'nfs',
    3306: 'mysql',
    3389: 'rdp',
    5432: 'postgresql',
    5500: 'vnc',
    5631: 'pcanywhere',
    6000: 'X11',
    6667: 'IRC',
    8001: 'http_8001',
    8080: 'http',
    2784: 'http_2784',
    31337: 'backdoor',
    60001: 'other',
    108: 'private',            # Private services
    115: 'remote_job',         # Remote Job Entry Protocol
    115: 'eco_i',              # Echo Protocol (Alternative)
    57:  'mtp',                # Mail Transfer Protocol
    53:  'domain_u',           # Domain Name Service (UDP)
    95:  'supdup',             # SUPDUP Terminal Protocol
    117: 'uucp_path',          # Unix-to-Unix Copy Path Service
    210: 'Z39_50',             # ANSI Z39.50
    105: 'csnet_ns',           # CSNET Name Service
    92:  'urp_i',              # Unreliable Remote Protocol
    123: 'ecr_i',              # Extended Clock Synchronization
    175: 'vmnet',              # VMNET Protocol
    11:  'systat',             # Active Users
    520: 'efs',                # Extended File Services
    102: 'iso_tsap',           # ISO Transport Service Access
    7:   'echo',               # Echo Protocol
    543: 'klogin',             # Kerberos Login
    87:  'link',               # Link Protocol
    544: 'kshell',             # Kerberos Remote Shell
    101: 'hostnames',          # NIC Host Name Server
    512: 'exec',               # Remote Process Execution
    9:   'discard',            # Discard Protocol
    530: 'courier',            # Courier Remote Procedure Call
    84:  'ctf',                # Common Trace Facility
    13:  'daytime',            # Daytime Protocol
    15:  'netstat',            # Network Status Monitoring
    433: 'nnsp',               # Network News Transfer Protocol Secure
    109: 'pop_2',              # Post Office Protocol 2
    208: 'tim_i',              # Timestamper Protocol
    300: 'pm_dump',            # Performance Metrics Dump
    336: 'red_i',              # RED-I Protocol
    405: 'urh_i',              # URH-I Protocol
    5190: 'aol',               # AOL Instant Messenger
    9999: 'harvest'            # Harvest Data Service
}
# Define a function to extract basic features
def extract_basic_features(packet, previous_packet):
    if 'src_port' in packet and 'dst_port' in packet:
        # Extract duration
        if previous_packet is not None:
            duration = packet['timestamp'] - previous_packet['timestamp']
        else:
            duration = 0

        # Extract protocol type
        protocol_type = packet['protocol']

        # Extract service
        service = port_to_service_map[packet['dst_port']] if packet['dst_port'] in port_to_service_map else 'other'

        # Extract flag
        flag = packet['tcp_flags']

        # Extract src bytes and dst bytes
        src_bytes = packet['packet_len']
        dst_bytes = packet['packet_len']

        # Extract land
        land = 1 if packet['src_ip'] == packet['dst_ip'] else 0

        # Extract wrong fragment
        wrong_fragment = 1 if packet['packet_len'] < 64 else 0

        # Extract urgent
        urgent = 1 if packet['tcp_flags'] == 0x20 else 0

        # Extract packet payload length
        packet_payload_len = len(packet['packet_payload'])

        # Extract source and destination IP address lengths
        src_ip_len = len(packet['src_ip'])
        dst_ip_len = len(packet['dst_ip'])

        # Extract source and destination port numbers
        src_port_num = packet['src_port']
        dst_port_num = packet['dst_port']

        # Extract ICMP type and code
        icmp_type_code = packet['icmp_type']
        icmp_code_code = packet['icmp_code']

        return {
            'duration': duration,
            'protocol_type': protocol_type,
            'service': service,
            'flag': flag,
            'src_bytes': src_bytes,
            'dst_bytes': dst_bytes,
            'land': land,
            'wrong_fragment': wrong_fragment,
            'urgent': urgent,
            'packet_payload_len': packet_payload_len,
            'src_ip_len': src_ip_len,
            'dst_ip_len': dst_ip_len,
            'src_port_num': src_port_num,
            'dst_port_num': dst_port_num,
            'icmp_type_code': icmp_type_code,
            'icmp_code_code': icmp_code_code
        }
    else:
        # Handle packets that do not have a TCP layer
        return None

# Define a function to capture packets and extract features
def capture_packets():
    # Capture packets using Scapy
    scapy.sniff(prn=process_packet, filter="ip", count=50)

    # Save the DataFrame to a CSV file
    csv_path = "captured_packets.csv"
    df.to_csv(csv_path, index=False)
    print("Data saved to captured_packets.csv")

     # Define destination directory
    destination_dir = "/home/bs00794/Documents/My_Projects/netprobe_lite/models/captured_packets.csv"
    
    # Move the CSV file
    shutil.move(csv_path, destination_dir)
    
    print(f"Data saved to {destination_dir}")

# Define a function to process a packet
previous_packet = None
def process_packet(packet):
    global previous_packet
    parsed_packet = parse_packet(packet)
    if parsed_packet is not None:
        if previous_packet is not None:
            features = extract_basic_features(parsed_packet, previous_packet)
        else:
            features = extract_basic_features(parsed_packet, None)
        if features is not None:
            # Append the features to the DataFrame
            global df
            df.loc[len(df)] = features
            
        previous_packet = parsed_packet

# Call the capture_packets function
capture_packets()
