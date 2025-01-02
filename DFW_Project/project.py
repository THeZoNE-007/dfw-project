from scapy.all import rdpcap, DNS, IP, ICMP, TCP, ARP
from collections import Counter
from collections import defaultdict
import time
import sys
import csv

###############################################################
#                  IP and MAC Address Columns                 #
###############################################################

def IP_to_MAC_mapping(packets):

    IP_mapTo_MAC = Counter() 

    for packet in packets:
        if packet.haslayer('IP') and packet.haslayer('Ether'):
            IP_mapTo_MAC[packet['IP'].src]=packet['Ether'].src
    
    return IP_mapTo_MAC

###############################################################
#       Rule 1: Detecting Traffic on Non-Standard Ports       #
###############################################################

def Non_Std_ports(packets):

    IP_with_non_standard_ports = set()

    for packet in packets:
        if packet.haslayer('TCP'):
            tcp_layer = packet['TCP']
            if tcp_layer.dport not in [80, 443, 22]:  # Adding standard destination ports
                if packet.haslayer('IP'):
                    IP_with_non_standard_ports.add(packet['IP'].src)

    return IP_with_non_standard_ports

###############################################################
#        Rule 2: High Traffic Volume (DDoS Detection)         #
###############################################################

def Potential_DDoS_IPs(packets):

    IP_THRESHOLD = 100
    ip_count = Counter() 

    for packet in packets:
        if packet.haslayer('IP'):
            ip_layer = packet['IP']
            ip_count[ip_layer.src] += 1

    ddos_candidates = [ip for ip, count in ip_count.items() if count > IP_THRESHOLD]

    return ddos_candidates

###############################################################
#          Rule 3: Detect IPs exceeding a threshold           #
###############################################################

def Large_pktSize_IPs(packets):

    MAX_MTU = 1500
    sizeExceed = set()

    for packet in packets:
        size = len(packet)
        if size > MAX_MTU:
            if packet.haslayer('IP'):
                sizeExceed.add(packet['IP'].src)

    return sizeExceed

################################################################
#               Rule 4: Unsolicitated ARP replies              #
################################################################

def ARPreply_unsolicitated(packets):

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

def Unusual_LargeDNS(packets):
   
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
#                   Rule 6: Excess ICMP Requests               #
################################################################

def ExcessICMP(packets):

    TIME_WINDOW = 60  # Time window in seconds
    ICMP_THRESHOLD = 10  # Maximum number of ICMP Echo Requests within the time window

    icmpRequests = defaultdict(list)  # Dictionary to store timestamps of ICMP Echo Requests
    excessiveICMP = []  # List to store IP addresses with excessive ICMP activity

    for packet in packets:
        if packet.haslayer(ICMP):
            icmpLayer = packet[ICMP]
            if icmpLayer.type == 8:  # ICMP Echo request (Type 8 packet)
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

def IPs_scanning_excess_ports(packets):

    PORT_SCAN_THRESHOLD = 5  # connection attempts on multiple ports from the same IP
    connection_attempts = defaultdict(set)  # Source IP -> Set of Destination ports
    multiPortScans = set()
    for packet in packets:
        if packet.haslayer(TCP):
            tcp_layer = packet['TCP']
            if packet.haslayer(IP):
                connection_attempts[packet[IP].src].add(tcp_layer.dport)

    for ip, ports in connection_attempts.items():
        if len(ports) > PORT_SCAN_THRESHOLD:
            multiPortScans.add(ip)
    
    return multiPortScans

################################################################
#                     Writing the CSV File                     #
################################################################

def MDP_Calculator(conditions):
    # Initializing a counter for satisfied rules
    satisfied_rules = 0

    # Loop through the first 8 conditions
    for i in range(min(8, len(conditions))):
        if conditions[i] == 1:
            satisfied_rules += 1

    MDP_percentage = (satisfied_rules * 100) / 8

    return MDP_percentage               


def ReportGen(IPnMAC, C1, C2, C3, C4, C5, C6, C7, C8):
    with open("outputReport.csv",'w+') as file:
        file.writelines("IP_Address\tMAC_Address\tNon-Std_Ports\tPotential_DDoS\tL_Pkt_Size\tUnsolicitated_ARP_Replies\tUnusually_L_DNS\tExcessive_ICMP_Echo_Req\tExcessive_TCP_SYN\tExcessive_Port_Scanning\tMDP(%)\n")
        for ip,mac in IPnMAC.items():
            columns=[]
            columns.append(1 if ip in C1 else 0) # Rule 1
            columns.append(1 if ip in C2 else 0) # Rule 2
            columns.append(1 if ip in C3 else 0) # Rule 3
            columns.append(1 if ip in C4 else 0) # Rule 4
            columns.append(1 if ip in C5 else 0) # Rule 5
            columns.append(1 if ip in C6 else 0) # Rule 6
            columns.append(1 if ip in C7 else 0) # Rule 7
            columns.append(1 if ip in C8 else 0) # Rule 8
            MDP_SCORE=MDP_Calculator(columns)    # MDP Score calculation
            file.writelines(f"{ip}\t{mac}\t{columns[0]}\t{columns[1]}\t{columns[2]}\t{columns[3]}\t{columns[4]}\t{columns[5]}\t{columns[6]}\t{columns[7]}\t{MDP_SCORE}\n")
        else:
            print("!! REPORT GENERATED !!")
        file.close()

################################################################
#                   Main function of the Code                  #
################################################################

# Load the PCAP file
filepath = sys.argv[1]
packets = rdpcap(filepath)

# Initiating variables
IP_MAC = IP_to_MAC_mapping(packets)
Rule_01 = Non_Std_ports(packets)
Rule_02 = Potential_DDoS_IPs(packets)
Rule_03 = Large_pktSize_IPs(packets)
Rule_04 = ARPreply_unsolicitated(packets)
Rule_05 = Unusual_LargeDNS(packets)
Rule_06 = ExcessICMP(packets)
Rule_07 = TCP_SYN_Flood(packets)
Rule_08 = IPs_scanning_excess_ports(packets)

# Report generation
ReportGen(IP_MAC, Rule_01, Rule_02, Rule_03, Rule_04, Rule_05, Rule_06, Rule_07, Rule_08)
