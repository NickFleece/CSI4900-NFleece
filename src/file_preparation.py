import random
from scapy.all import *
from scapy.layers.dns import DNSRR, DNS, DNSQR
from scapy.layers.ipsec import IP, UDP, IPv6
import pandas as pd
import glob
import os
import threading
import queue
import datetime

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

                "srcAddress": None,  # done as a check for ip vs ipv6
                "srcPort": packet[UDP].sport,
                "length": len(packet),
                "dstAddress": None,  # done as a check for ip vs ipv6,
                "opcode": packet[DNS].opcode,
                "status": packet[DNS].rcode,

                "responseFlag": packet[DNS].qr,
                "authoritativeFlag": packet[DNS].aa,
                "truncationFlag": packet[DNS].tc,

                "questionName": packet.qd.qname,
                "questionType": packet.qd.qtype,

                # below is handled differently for responses vs queries
                "answerCount": packet[DNS].ancount,
                "answerTypes": None,  # done in if statement after this
                "answerTTLS": None,  # done in if statement after this
                "answerData": None,  # done in if statement after this
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


def clean_pcap(file, queue=None):
    count = 0
    clean_packets = []
    for p in PcapReader(file):
        count += 1
        if count % 10000 == 0:
            clean_number = '{:,}'.format(count)
            print(f"Cleaned {clean_number} -- {file}")
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
            if len(clean_packets) > 1000:
                if queue == None:
                    write_cleaned_packets(file, clean_packets)
                else:
                    queue.put(clean_packets)
                clean_packets = []
    if queue == None:
        write_cleaned_packets(file, clean_packets)
    else:
        queue.put(clean_packets)

def write_cleaned_packets(fileName, packets):
    print(f"Writing {len(packets)} packets to pcap...")
    wrpcap(f"{fileName}_cleaned.pcap", packets, append=True)


def clean_and_combine_pcap_files(directory):
    print(f"Combining pcap files at directory: {directory}")

    print("Making all files .pcap files...")
    files = glob.glob(directory + "/*/*", recursive=True)
    for file in files:
        if file[-5:] != ".pcap":
            os.rename(file, file + ".pcap")

    print("Combining all pcap files into one")
    files = glob.glob(directory + "/*/*.pcap")
    que = queue.Queue()
    threads = []
    for file in files:
        print(f"Starting processing on file {file}...")
        thread = threading.Thread(target=clean_pcap, args=(file, que))
        thread.start()
        threads.append(thread)
        while len(threads) == 1:
            print("At max threads, waiting for one to finish...")
            while que.qsize() == 0:
                print("Queue empty, waiting...")
                time.sleep(1)
            while que.qsize() > 0:
                packets = que.get()
                print(f"Writing {len(packets)} to combined file - {datetime.datetime.now()}...")
                wrpcap(f"{directory}/combined.pcap", packets, append=True)
            print("Looking for threads to remove...")
            for t in threads:
                if not t.isAlive():
                    print("Removing a thread...")
                    threads.remove(t)

# loads a pcap into memory
# THIS MAY TAKE A VERY LONG TIME FOR LARGE PCAP FILES
def load_pcap(fileName, trueFileRoute=False):
    count = 0
    outputPackets = []
    if not trueFileRoute:
        fileName = f"../../Files/{fileName}.pcap"
    for p in PcapReader(fileName):
        count += 1
        if count % 10000 == 0:
            clean_number = '{:,}'.format(count)
            print(f"Loaded {clean_number} packets into memory")
        outputPackets.append(p)
    return outputPackets


clean_and_combine_pcap_files("D:/traffic_data/Big_Files")
# malicious_data = load_pcap("malicious")
# benign_data = load_pcap("benign")
# joined = shuffle_file_data(benign_data, malicious_data)
# packets_to_csv(joined)
