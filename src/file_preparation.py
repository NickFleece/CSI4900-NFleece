import csv
import random
from scapy.all import *
from scapy.layers.dns import DNSRR, DNS, DNSQR

def shuffle_combine_files(file1Data, file2Data):
    file1headers = file1Data.pop(0)
    file2headers = file2Data.pop(0)
    if file1headers != file2headers:
        print("The headers should be the same!")
    else:
        joinedFileData = file1Data + file2Data
        random.shuffle(joinedFileData)
        joinedFileData = [file1headers] + joinedFileData
        with open(f"../../Files/joined_data.csv", 'w', newline='') as writeFile:
            writer = csv.writer(writeFile)
            writer.writerows(joinedFileData)
    return None

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
        #2. Is a response (only care about queries
        #3. Response is not an OK from the server
        if not p.haslayer(DNS) or p.ancount > 0 or p[DNS].rcode != 0:
            continue
        if p.qdcount > 0 and isinstance(p.qd, DNSQR):
            name = p.qd.qname
            type = p.qd.qtype
        else:
            continue
        if name != None and type in [1, 28]:
            clean_packets.append(p)
            if len(clean_packets) > 10000:
                write_packets(fileName, clean_packets)
                clean_packets = []
    write_packets(fileName, clean_packets)

def write_packets(fileName, packets):
    print(f"Writing {len(packets)} packets to pcap...")
    wrpcap(f"../../Files/{fileName}_cleaned.pcap", packets, append=True)
    # count = 0
    # for p in packets:
    #     count += 1
    #     if count % 1000 == 0:
    #         clean_number = '{:,}'.format(count)
    #         print(f"Wrote {clean_number} / {len(packets)}")
    #     wrpcap(f"../../Files/{fileName}_cleaned.pcap", p, append=True)

# main()
clean_pcap("appDDos_cleaned")