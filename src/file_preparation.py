import random
from scapy.all import *
from scapy.layers.dns import DNSRR, DNS, DNSQR
from scapy.layers.ipsec import IP, UDP, IPv6
import pandas as pd


def packets_to_csv(packets):

    totalData = []

    count = 0
    print(f"Writing {len(packets)} packets to csv")

    for packet in packets:
        malicious = packet[0]
        packet = packet[1]

        try:
            count += 1
            if count % 10000 == 0:
                print(f"{count} packets!")

            data = {
                "malicious": malicious,

                "srcAddress": None, #done as a check for ip vs ipv6
                "srcPort": packet[UDP].sport,
                "length": len(packet),
                "dstAddress": None, #done as a check for ip vs ipv6,
                "opcode": packet[DNS].opcode,
                "status": packet[DNS].rcode,

                "responseFlag": packet[DNS].qr,
                "authoritativeFlag": packet[DNS].aa,
                "truncationFlag": packet[DNS].tc,

                "questionName": packet.qd.qname,
                "questionType": packet.qd.qtype,

                #below is handled differently for responses vs queries
                "answerCount": packet[DNS].ancount,
                "answerTypes": None, #done in if statement after this
                "answerTTLS": None, #done in if statement after this
                "answerData": None, #done in if statement after this
                # "answerCanonical": None, #?
                # "answerAddress": None #done in if statement after this
            }

            if packet[DNS].ancount > 0:
                data["answerTypes"] = packet[DNS].an.type
                data["answerTTLS"] = packet[DNS].an.ttl
                data["answerData"] = packet[DNS].an.rdata
                # data["answerAddress"] = packet[DNS].an.rdata

            if packet.haslayer(IP):
                data["srcAddress"] = packet[IP].src
                data["dstAddress"] = packet[IP].dst
            elif packet.haslayer(IPv6):
                data["srcAddress"] = packet[IPv6].src
                data["dstAddress"] = packet[IPv6].dst
            else:
                print(f"Ignoring a packet because it doesn't have IP or IPv6: {packet.qd.qname}")
                continue

            totalData.append(data)
        except Exception as e:
            print(f"Error with packet, trying to send to address {packet.qd.qname}, with error: {e}")
            continue

    df = pd.DataFrame(data=totalData)
    df.to_csv("../data/full_data.csv")


def shuffle_file_data(benignPackets, maliciousPackets):
    for i in range(0, len(benignPackets)):
        benignPackets[i] = [0, benignPackets[i]]
    for j in range(0, len(maliciousPackets)):
        maliciousPackets[j] = [1, maliciousPackets[j]]
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
        # conditions for not caring about the packet:
        # 1. Does not have DNS layer
        # 2. Is a response (only care about queries)
        # 3. Response is not an OK from the server
        if not p.haslayer(DNS) or (p.ancount > 0 or p.nscount > 0 or p[DNS].ra != 0) or p[DNS].rcode != 0:
            continue
        if p.qdcount > 0 and isinstance(p.qd, DNSQR):
            name = p.qd.qname
            type = p.qd.qtype
        else:
            continue
        # make sure DNS query has a name and that it is a A or AAAA type
        if name != None and type in [1, 28]:
            clean_packets.append(p)
            if len(clean_packets) > 10000:
                write_cleaned_packets(fileName, clean_packets)
                clean_packets = []
    write_cleaned_packets(fileName, clean_packets)


def write_cleaned_packets(fileName, packets):
    print(f"Writing {len(packets)} packets to pcap...")
    wrpcap(f"../../Files/{fileName}_cleaned.pcap", packets, append=True)


# loads a pcap into memory
# THIS MAY TAKE A VERY LONG TIME FOR LARGE PCAP FILES
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
benign_data = load_pcap("benign")
joined = shuffle_file_data(benign_data, malicious_data)
packets_to_csv(joined)