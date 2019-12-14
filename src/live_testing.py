from scapy.all import *
from file_preparation import *
from feature_generation import *
from machine_learning import *

def packet_in(pkt):
    # print("Found packet...")
    parsed = packets_to_csv([[None,pkt]], returnArrayWithNoOutput=True)
    features = generate_features(None, packetArray=parsed, returnArrayWithNoOutput=True)
    results = predict_packet(features)

    malicious = False
    for model in results.keys():
        if results[model][0] > 0.5:
            print(f"{model} has found a dns packet that is attempting to exfiltrate data! {pkt.qd.qname}")
            malicious = True
    if malicious:
        print("\n-----\n")

def start_sniffing():
    print("Starting sniffing!\n")
    # interface = 'Wi-Fi'
    filter_bpf = 'port 53'
    sniff(filter=filter_bpf, prn=packet_in)

start_sniffing()