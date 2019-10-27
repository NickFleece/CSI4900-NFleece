import random
from scapy.all import *
from scapy.layers.dns import DNSRR, DNS, DNSQR

def shuffle_file_data(benignPackets, maliciousPackets):
    joinedPackets = benignPackets + maliciousPackets
    random.shuffle(joinedPackets)
    return joinedPackets

def clean_pcap(fileName):
    count = 0
    clean_packets = []
    for p in PcapReader(f"../../Files/{fileName}.pcap"):
        count += 1
        if count % 10000 == 0:
            clean_number = '{:,}'.format(count)
            print(f"Cleaned {clean_number}")
        #conditions for not caring about the packet:
        #1. Does not have DNS layer
        #2. Is a response (only care about queries)
        #3. Response is not an OK from the server
        if not p.haslayer(DNS) or (p.ancount > 0 or p.nscount > 0 or p[DNS].ra != 0) or p[DNS].rcode != 0:
            continue
        if p.qdcount > 0 and isinstance(p.qd, DNSQR):
            name = p.qd.qname
            type = p.qd.qtype
        else:
            continue
        #make sure DNS query has a name and that it is a A or AAAA type
        if name != None and type in [1, 28]:
            clean_packets.append(p)
            if len(clean_packets) > 10000:
                write_cleaned_packets(fileName, clean_packets)
                clean_packets = []
    write_cleaned_packets(fileName, clean_packets)

def write_cleaned_packets(fileName, packets):
    print(f"Writing {len(packets)} packets to pcap...")
    wrpcap(f"../../Files/{fileName}_cleaned.pcap", packets, append=True)

#loads a pcap into memory
#THIS MAY TAKE A VERY LONG TIME FOR LARGE PCAP FILES
def load_pcap(fileName):
    count = 0
    outputPackets = []
    for p in PcapReader(f"../../Files/{fileName}.pcap"):
        count += 1
        if count % 1000 == 0:
            clean_number = '{:,}'.format(count)
            print(f"Loaded {clean_number} packets into memory")
        outputPackets.append(p)
    return outputPackets

malicious_data = load_pcap("malicious")
benign_data = load_pcap("appDDos_cleaned")
joined = shuffle_file_data(benign_data, malicious_data)
wrpcap("../../Files/joined_data.pcap", joined, append=True)