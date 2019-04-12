'''
Alex Lee
Python Port Scanner
'''
import sys
from scapy.all import *
import re
import socket
import random


def main():
    if len(sys.argv) != 4:
        print("Usage: sudo python {} TLP IP Ports".format(sys.argv[0]))
        print("\tTLP: \"T\" TCP, \"U\" UDP")
        print("\tIP: IPv4 Address of target to scan")
        print("\tPorts: Port (80) or range of ports to scan (1-80)")
        return

    TLP = sys.argv[1]
    dstIP = sys.argv[2]
    Ports = sys.argv[3]

    # Validate TLP
    if TLP != "T" and TLP != "U":
        print ("Err: Invalid TLP. [T/U]")
        return
    if TLP == "T":
        protocol = "TCP"
    else:
        protocol = "UDP"

    # Validate IP address
    ipPattern = re.compile('^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$')
    if not ipPattern.match(dstIP):
        print ("Err: Invalid IPv4 Address")
        return

    #Validate ports
    portPattern = re.compile('^([0-9]{1,4}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])([-]([0-9]{1,4}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5]))?$')
    if not portPattern.match(Ports):
        print ("Err: Invalid Ports")
        return

    print ("Protocol {}\nTarget {}\nPorts {}".format(protocol, dstIP, Ports))

    # Convert range of ports to a list of ports.
    Ports = Ports.split("-")
    if len(Ports) == 1:
        Ports = [int(Ports[0])]

    else:
        temp = []
        for p in range(int(Ports[0]), int(Ports[1])):
            temp.append(p)
        temp.append(int(Ports[1]))
        Ports = temp
        random.shuffle(Ports)
    print ("{} Scanning Starts ...".format(protocol))

    conf.verb = 0
    if protocol == "TCP":
        for port in Ports:
            #Generate packet and send
            sp =RandShort()
            ip = IP(dst = dstIP)
            tcp = TCP(sport = sp, dport = port, flags = "S")
            pkt = ip/tcp
            a = sr1(pkt, timeout = 2)

            # No Response. Timeout. Port is Filtered
            if a == None:
                print("Port: {}\tStatus: {}\tReason: {}".format(port, "Filtered", "No Response"))
            else:
                flag = a.getlayer(TCP).flags

                #SYNACK flag received. Open. Send RST
                if flag == 18:
                    print("Port: {}\tStatus: {}\t\tReason: {}".format(port, "Open", "Received TCP SYN-ACK"))
                    rst = ip/TCP(sport = sp , dport = port, flags = "R")
                    send(rst)

                #RST flag received. Closed
                elif flag == 20:
                    print("Port: {}\tStatus: {}\tReason: {}".format(port, "Closed", "Received TCP RST"))


    if protocol == "UDP":
        for port in Ports:
            #Generate Packet and send
            sp =RandShort()
            ip = IP(dst = dstIP)
            udp = UDP(sport = sp, dport = port)
            pkt = ip/udp
            a = sr1(pkt, timeout = 2)
            # No Response. Filtered
            if a == None:
                print("Port: {}\tStatus: {}\tReason: {}".format(port, "Open|Filtered", "No Response"))
            else:
                flags = a.getlayer(ICMP).flags
                if flags == 0:
                    print("Port: {}\tStatus: {}\tReason: {}".format(port, "Closed", "Received ICMP Port Unreachable"))

if __name__ == "__main__":
    main()
