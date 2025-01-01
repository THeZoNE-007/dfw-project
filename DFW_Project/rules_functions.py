from scapy.all import rdpcap, DNS, IP, ICMP, TCP, ARP
from collections import Counter
from collections import defaultdict
import time

import sys
import csv

################################################################
#                   Main function of the Code                  #
################################################################

# Load the PCAP file
filepath = sys.argv[1]
packets = rdpcap(filepath)

IP_mapTo_MAC = Counter()
for packet in packets:
    if packet.haslayer('IP') and packet.haslayer('Ether'):
        IP_mapTo_MAC[packet['IP'].src]=packet['Ether'].src
print(f"{IP_mapTo_MAC}")

###############################################################
#       Rule 1: Detecting Traffic on Non-Standard Ports       #
###############################################################

# Inspect packets
for packet in packets:
    print(packet.summary())

non_standard_ports = set()

for packet in packets:
    if packet.haslayer('TCP'):
        tcp_layer = packet['TCP']
        if tcp_layer.dport not in [80, 443, 22]: # Add standard destination ports
            non_standard_ports.add(tcp_layer.dport)
print("Non-standard ports detected:",non_standard_ports)

###############################################################
#        Rule 2: High Traffic Volume (DDoS Detection)         #
###############################################################

ip_count = Counter()

for packet in packets:
    if packet.haslayer('IP'):
        ip_layer = packet['IP']
        ip_count[ip_layer.src] += 1

###############################################################
#          Rule 3: Detect IPs exceeding a threshold           #
###############################################################

def potential_ddos_ips(packets):
  """
  Identifies potential DDoS attack sources based on IP address frequency and packet size.

  Args:
    packets: A list of packet objects.

  Returns:
    A list of IP addresses that are potential DDoS attack sources.
  """

  IP_THRESHOLD = 100  # Set threshold
  MAX_MTU = 1500
  sizeExceed = set()
  ip_count = Counter() 

  for packet in packets:
    if packet.haslayer('IP'):
      ip_layer = packet['IP']
      ip_count[ip_layer.src] += 1

  ddos_candidates = [ip for ip, count in ip_count.items() if count > IP_THRESHOLD]

  for packet in packets:
    size = len(packet)
    if size > MAX_MTU:
      if packet.haslayer('IP'):
        sizeExceed.add(packet['IP'].src)

  # Find intersection of ddos_candidates and IPs with large packets
  potential_ddos_ips = set(ddos_candidates).intersection(sizeExceed) 

  return list(potential_ddos_ips)

################################################################
#               Rule 4: Unsolicitated ARP replies              #
################################################################

def ARPreply_unsolicitated(packets):
    """
    Detects unsolicited ARP replies.

    Args:
        packets: A list of packet objects.

    Returns:
        A set of IP addresses that have sent unsolicited ARP replies.
    """

    arpRequests = set()  # Store unique ARP requests
    unsolicited_replies = set()  # Store unique unsolicitated replies

    for packet in packets:
        if packet.haslayer(ARP):
            arpLayer = packet[ARP]
            match arpLayer.op:
                case 1:  # opcode flag = 1 ---> ARP Request
                    arpRequests.add(arpLayer.psrc)
                case 2:  # opcode flag = 2 ---> ARP Reply
                    if arpLayer.psrc not in arpRequests:
                        unsolicited_replies.add(arpLayer.psrc)

    return unsolicited_replies

################################################################
#             Rule 5: Unusually Large DNS Responses            #
################################################################

def unusualLargeDNS(packets):
    """
    Detects unusually large DNS response packets.

    Args:
        packets: A list of packet objects.

    Returns:
        A list of packets that are larger than the specified DNS_THRESHOLD.
    """

    DNS_THRESHOLD = 512  # Threshold for large DNS response size in bytes

    largeDNSresponse = []

    for packet in packets:
        if packet.haslayer(DNS) and packet.haslayer(IP):
            dnsLayer = packet[DNS]
            if dnsLayer.qr == 1:  # qr flag = 1 ---> DNS Response
                if len(packet) > DNS_THRESHOLD:  # Checking for any DNS > threshold
                    largeDNSresponse.append(packet)

    return largeDNSresponse

################################################################
#                     Rule 6: Excess ICMP Requests             #
################################################################

def ExcessICMP(packets):
    """
    Detects excessive ICMP Echo Request (ping) activity from different IP addresses.

    Args:
        packets: A list of packet objects.

    Returns:
        A list of IP addresses that have sent an excessive number of ICMP Echo Requests 
        within the specified time window.
    """

    TIME_WINDOW = 60  # Time window in seconds
    ICMP_THRESHOLD = 10  # Maximum number of ICMP Echo Requests within the time window

    icmpRequests = defaultdict(list)  # Dictionary to store timestamps of ICMP Echo Requests
    excessiveICMP = []  # List to store IP addresses with excessive ICMP activity

    for packet in packets:
        if packet.haslayer(ICMP):
            icmpLayer = packet[ICMP]
            if icmpLayer.type == 8:  # ICMP Echo request (ping)
                src_ip = packet[IP].src
                timestamp = packet.time  # Timestamp of the packet

                # Append the timestamp of the ICMP Echo request for this source IP
                icmpRequests[src_ip].append(timestamp)

                # Remove timestamps that are outside the time window
                icmpRequests[src_ip] = [t for t in icmpRequests[src_ip] if timestamp - t <= TIME_WINDOW]

                # Check if the number of requests exceeds the threshold within the time window
                if len(icmpRequests[src_ip]) > ICMP_THRESHOLD:
                    if src_ip not in excessiveICMP:
                        excessiveICMP.append(src_ip)

    return excessiveICMP

################################################################
#   Rule 7: Detect TCP SYN Flood (High number of SYN packets)  #
################################################################

def TCP_SYN_Flood(packets):
    """
    Detects potential TCP SYN floods based on the number of SYN packets 
    received from the same IP address within a short period.

    Args:
        packets: A list of packet objects.

    Returns:
        A set of IP addresses suspected of initiating a SYN flood.
    """

    SYN_FLOOD_THRESHOLD = 100  # No. of SYN packets in a short period
    syn_count = defaultdict(int)
    floodOfIP = set()

    for packet in packets:
        if packet.haslayer(TCP) and packet['TCP'].flags == 0x02:  # Check for SYN flag
            src_ip = packet['IP'].src
            syn_count[src_ip] += 1

    for ip, count in syn_count.items():
        if count > SYN_FLOOD_THRESHOLD:
            floodOfIP.add(ip)

    return floodOfIP

################################################################
#                Rule 8: Port Scanning Detection               #
################################################################

def portScanDetection(packets):
    """
    Detects potential port scans based on the number of connection attempts 
    to different ports from the same IP address.

    Args:
        packets: A list of packet objects.

    Returns:
        A list of ports that attempted multiple port scans from same IP
    """

    PORT_SCAN_THRESHOLD = 5  # connection attempts on multiple ports from the same IP
    connection_attempts = defaultdict(set)  # Source IP -> Set of Destination ports
    multiPortScans = set()
    for packet in packets:
        if packet.hasLayer(TCP):
            tcp_layer = packet['TCP']
            if packet.haslayer(IP):
                connection_attempts[packet[IP].src].add(tcp_layer.dport)

    for ip, ports in connection_attempts.items():
        if len(ports) > PORT_SCAN_THRESHOLD:
            multiPortScans.add(ip)
    
    return multiPortScans


################################################################
#                      Writing the CSV File                    #
################################################################

def calculateMDP(rule):
    MDP = 0
    for rules in rule:
        if(rules == 1):
            MDP += 10
    return MDP        
 
        

def ReportGen(ipMacs,NSPs,ddos_ip,exceed_size_ips,FloodIps,multipleScan,unsolicatedArp,largeDNS,excessICMP):
    with open("outputReport.csv",'w+') as file:
        file.writelines("IP\t\tMAC\t\t\tNSP\tDDOS\tExceedingIPs\tSYN-flood-ip\tMultiport-scan\tUnsolicated-ARP\tlarge-DNS  Excess-ICMP      MDP(%)\n")
        for ip,mac in ipMacs.items():
            rule=[]
            rule.append(1 if ip in NSPs else 0)
            rule.append(1 if ip in ddos_ip else 0)
            rule.append(1 if ip in exceed_size_ips else 0)
            rule.append(1 if ip in FloodIps else 0)
            rule.append(1 if ip in multipleScan else 0)
            rule.append(1 if ip in unsolicatedArp else 0)
            rule.append(1 if ip in largeDNS else 0)
            rule.append(1 if ip in excessICMP else 0)
            MDP_SCORE=calculateMDP(rule)
            file.writelines(f"{ip}\t{mac}\t{rule[0]}\t{rule[1]}\t\t{rule[2]}\t\t{rule[3]}\t\t{rule[4]}\t\t{rule[5]}\t\t{rule[6]}\t{rule[7]}\t\t{MDP_SCORE}\n")
        file.close()
