'''
Alex Lee
Python Traceroute

Usage: sudo python traceroute.py [ip address]

Use regular expressions to check if arguments matches IPv4 address
Use Socket to get current IPv4 Address
Create packet using IP and UDP
Set TTL of IP packet to 1
Send packet and print the ip address from the ICMP response
Recreate and resend the packet, changing the UDP and incrementing the TTL by 1
Repeat until ICMP host unreachable is received
'''

from scapy.all import *
import socket
import sys
import re

conf.verb = 0
def main():

    #checks if arguments provided are valid
    if len(sys.argv) != 2:
        print "Usage: sudo python", sys.argv[0], "[ip address]"
    dst = sys.argv[1]
    #regular expressions for IP address
    ipPattern = re.compile('^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$')

    #check if destination IP matches with the Regex
    if not ipPattern.match(dst):
        print "Err: Invalid IP\n\tUsage: sudo python", sys.argv[0], "[ip address]"
        return 0;


    #use socket to get the local IP address
    sport = random.randrange(30000, 50000)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect((dst, sport))
    src = s.getsockname()[0]
    s.close();

    #loop this 20 times.
    maxHops = 20;
    for i in range(1, maxHops +1):

        #set the destination port to be a random port number between 33434 and 33464
        dport = random.randrange(33434, 33464)

        #set src and dst for IP
        #TTL is is equal to the current iteration of the loop and increments by 1 each time
        ip = IP(src = src, dst = dst, ttl = i)
        udp = UDP(sport = sport, dport = dport)

        #set the packet and send
        pkt = ip/udp
        ans, unans = sr(pkt, timeout = 3)

        #Unreachable if no answer is received
        if len(ans) == 0:
            print i, "\t****"
        else:
            #print the src ip of the returning ICMP
            retIP = str(ans[0][1].getlayer(IP).src)
            print i, "\t", retIP
            #if icmp host unreachable is received, break.
            if ans[0][1].getlayer(ICMP).code == 3:
                break


if __name__ == "__main__":
    main()