import random
import multiprocessing
from scapy.all import *
from scapy.layers.dns import DNSRR, DNS, DNSQR
from scapy.layers.ipsec import IP, UDP, IPv6
import pandas as pd
import glob
import os
from multiprocessing import Queue
import datetime

def packets_to_csv(packets, returnArrayWithNoOutput = False):
    totalData = []

    count = 0

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

                "questionName": str(packet.qd.qname),
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

    if not returnArrayWithNoOutput:
        df = pd.DataFrame(data=totalData)
        df.to_csv("../data/full_data.csv")
    else:
        return totalData


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
    dnsCount = 0
    clean_packets = []
    print(f"Starting cleaning on file {file}...")
    for p in PcapReader(file):
        count += 1
        if count % 5000 == 0:
            clean_number = '{:,}'.format(count)
            print(f"Cleaned {clean_number} -- {file}")
        if count == 100000 and dnsCount == 0:
            print("No dns packets in first 100,000: Not worth processing, Exiting")
            break
        # conditions for not caring about the packet:
        # 1. Does not have DNS layer
        # 2. Response is not an OK from the server
        if not p.haslayer(DNS):
            continue
        if p[DNS].rcode != 0:
            continue
        if p.qdcount > 0 and isinstance(p.qd, DNSQR):
            name = p.qd.qname
            type = p.qd.qtype
        else:
            continue
        # make sure DNS query has a name and that it is a A or AAAA type
        if name != None and type in [1, 28]:
            clean_packets.append(p)
            dnsCount += 1
            if len(clean_packets) > 500:
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
    h = abs(hash(directory))

    print("Making all files .pcap files...")
    files = glob.glob(directory + "/*", recursive=True)
    for file in files:
        if file[-5:] != ".pcap":
            os.rename(file, file + ".pcap")

    print("Combining all pcap files into one")
    files = glob.glob(directory + "/*.pcap")
    que = Queue()
    threads = []
    prevTime = None
    count = 0
    for file in files:
        if prevTime != None:
            currTime = datetime.datetime.now()
            print(f"------------- Estimated time left: {(currTime - prevTime) * (len(files) - count)} : file {count} / {len(files)}")
            prevTime = currTime
        else:
            prevTime = datetime.datetime.now()
        count += 1

        print(f"Starting processing on file {file}...")
        thread = threading.Thread(target=clean_pcap, args=(file, que))
        # thread = multiprocessing.Process(target=clean_pcap, args=(file, que))
        thread.start()
        threads.append(thread)
        while len(threads) == 1:
            print("At max threads, waiting for one to finish...")
            while que.qsize() == 0:
                # print("Queue empty, waiting...")
                time.sleep(3)
            while que.qsize() > 0:
                packets = que.get()
                print(f"Writing {len(packets)} to combined file - {datetime.datetime.now()}...")
                wrpcap(f"{directory}/../combined_{h}.pcap", packets, append=True)
            print("Looking for threads to remove...")
            for t in threads:
                if not t.is_alive():
                    print("Removing a thread...")
                    threads.remove(t)
    for t in threads:
        while t.is_alive():
            time.sleep(3)
            print("Waiting for all threads to die...")
    while que.qsize() > 0:
        packets = que.get()
        print(f"Writing {len(packets)} to combined file - {datetime.datetime.now()}...")
        wrpcap(f"{directory}/../combined_{h}.pcap", packets, append=True)
    print("Done!")

def final_combine(directory):
    print(f"Combining pcap files at directory: {directory}")
    files = glob.glob(directory + "/*.pcap")
    for file in files:
        print(f"Parsing file: {file}")
        packets = []
        count = 0
        for packet in PcapReader(file):
            count += 1
            packets.append(packet)
            if len(packets) % 5000 == 0:
                print(f"{count} packets parsed, writing...")
                wrpcap(f"{directory}/all_combined.pcap", packets, append=True)
                packets = []
        print(f"Done file {file}, writing {len(packets)} remaining packets...")
        wrpcap(f"{directory}/all_combined.pcap", packets, append=True)
    print("Done!")

#remove packets from malicious pcap that aren't actually malicious
def clean_malicious(dir, file):
    print(f"Cleaning malicious file: {file}")
    new_packets = []
    count = 0
    for packet in PcapReader(f"{dir}{file}"):
        try:
            count += 1
            if len(new_packets) == 1000:
                print(f"Writing 1000 packets, {count} packets total parsed")
                wrpcap(f"{dir}cleaned_{file}", new_packets, append=True)
                new_packets = []
            if (packet.qd.qname).decode("utf-8")[-2] == "-":
                packet.qd.qname = packet.qd.qname[:-2]
                new_packets.append(packet)
        except Exception as e:
            print(f"{e}, skipping packet...")
    wrpcap(f"{dir}cleaned_{file}", new_packets, append=True)

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

def main():
    if __name__ == '__main__':
        print("Starting processing...")

        # clean_and_combine_pcap_files("E:/Big_Data_Files/BIG_PCAP")
        # clean_and_combine_pcap_files("E:/Big_Data_Files/PCAP-01-12_0250-0499")
        # clean_and_combine_pcap_files("E:/Big_Data_Files/PCAP-01-12_0500-0749")
        # clean_and_combine_pcap_files("E:/Big_Data_Files/PCAP-01-12_0750-0818")
        # clean_and_combine_pcap_files("E:/Big_Data_Files/random_files")
        # clean_and_combine_pcap_files("D:/traffic_data/Big_Files/appDDoS")
        #  ("D:/traffic_data/Big_Files/PCAP-03-11")
        # final_combine("D:/traffic_data/Big_Files")

        # clean_malicious("D:/traffic_data/malicious/", "lower_malicious.pcap")

        benign = load_pcap("D:/traffic_data/Big_Files/all_combined.pcap", True)
        malicious = load_pcap("D:/traffic_data/malicious/cleaned_lower_malicious.pcap", True)
        shuffled = shuffle_file_data(benign, malicious)
        packets_to_csv(shuffled)

# main()