import csv
from scapy.all import rdpcap, IP

# Open a CSV file for writing
with open('C:/Users/Jason/OneDrive/Desktop/WireShark Scans/ip_addresses.csv', 'w', newline='') as csvfile:
    fieldnames = ['Source IP', 'Destination IP']
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

    # Write the header row
    writer.writeheader()

    # Read the PCAP file
    packets = rdpcap("C:/Users/Jason/OneDrive/Desktop/WireShark Scans/Wireshark scans2.pcapng")

    # Loop through packets and write IP information (if present)
    for packet in packets:
        if IP in packet:
            source_ip = packet[IP].src
            destination_ip = packet[IP].dst
            writer.writerow({'Source IP': source_ip, 'Destination IP': destination_ip})