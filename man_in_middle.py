from scapy.all import *

#---- We only want to redirect traffic intended for the sensors
sensor_ip = '127.0.0.1'

def send_packet(packet):
    # print(packet.show(dump=True))
    if IP not in packet:
        return
    if UDP in packet:
        # print("UDP")
        # print(packet.show(dump=True))
        if packet[UDP].dport == 2368 or packet[UDP].dport == 2369:
            print(packet.show(dump=True))
            exit()
            if packet[UDP].dport == 2368:
                packet[IP].src = "10.31.32.248"
            else:
                packet[IP].src = "10.31.32.247"
            packet[UDP].sport = 2368
            packet[UDP].dport = packet[UDP].dport * 10
            sendp(packet)
    # if (packet[IP].dst == sensor_ip):
    #     print("For the sensor")

sniff(prn=send_packet, store=0, iface="lo")
