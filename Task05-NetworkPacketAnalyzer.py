"""Task05-Simple Network Packet Sniffer"""
#Using the scapy network to handle packets
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.packet import Raw


#Function to Process all Captured Packets

def Process_Captured_Packet(packet):
    if IP in packet:
        IP_Layer = packet[IP]
        protocol = IP_Layer.proto
        Source_IP = IP_Layer.src
        Destination_IP=IP_Layer.dst

        protocol_name =""
        if protocol ==1:
            protocol_name = "ICMP"
        elif protocol ==6:
            protocol_name= "TCP"
        elif protocol ==17:
            protocol_name = "UDP"
        else:
            protocol_name = "Unknown Protocol- Cannot Be Identified"


        #Printing the Captured Packet Details
        print(f"Protool: {protocol_name}")
        print(f"Source IP: {Source_IP}")
        print(f"Destination IP: {Destination_IP}")

        if protocol_name == "TCP" and TCP in packet:
            Source_port = packet[TCP].sport
            Destination_port = packet[TCP].dport
            print(f"Source Port: {Source_port}, Destination Port: {Destination_port}")
        elif protocol_name == "UDP" and UDP in packet:
            Source_port = packet[UDP].sport
            Destination_port = packet[UDP].dport
            print(f"Source Port: {Source_port}, Destination Port: {Destination_port}")

        if packet.haslayer(Raw):
            payload_data = packet[Raw].load
            print(f"Payload: {payload_data}")

        #Logging the Captured and Processed Packets on A file
        with open("packets_log.txt", "a") as log_file:
            log_file.write(f"Protocol: {protocol_name}\n")
            log_file.write(f"Source IP: {Source_IP}\n")
            log_file.write(f"Destination IP: {Destination_IP}\n")
            if protocol_name in ["TCP", "UDP"]:
                log_file.write(f"Source Port: {Source_port}, Destination Port: {Destination_port}\n")
            if packet.haslayer(Raw):
                log_file.write(f"Payload: {payload_data}\n")
            log_file.write("-" * 50 + "\n")

        print("*-" * 10)
#Function to run main method
def main():
    #Capture Packets on the default network interface
    try:
         print(f"Starting to sniff and capture packets")
         sniff(prn=Process_Captured_Packet,filter="ip", store=0)
    except Exception as e:
         print(f"Error Occured While Attempting to Sniff Packets")

if __name__ =="__main__":
    main()


