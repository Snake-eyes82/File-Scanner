#from scapy.all import rdpcap
from scapy.all import rdpcap, IP

# Read the PCAP file
packets = rdpcap("C:/Users/Jason/OneDrive/Desktop/WireShark Scans/Wireshark scans2.pcapng")

# Print header
# Print the header with a clear separation between columns
print("{:<15} {:<15}".format("Source IP", "Destination IP"))
print("-" * 35)

# Loop through packets and access IP information (if present)
for packet in packets:
    if IP in packet:
        source_ip = packet[IP].src
        destination_ip = packet[IP].dst
        print("{:<15} {:<15}".format(source_ip, destination_ip))