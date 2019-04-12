from scapy.all import *
import netifaces
import socket
import netaddr
import sys
import string
conf.verb = 0
def main():

    #Get list of all network interfaces and print the names
    print "Interfaces:"
    interfaces = netifaces.interfaces()
    for i in interfaces:
        print "\t", i

    #print the IP and MAC address of all the interfaces
    print "----\nInterface details:\n"
    for i in interfaces:
        address = netifaces.ifaddresses(i)

        netInfo = address[netifaces.AF_INET][0]
        hwInfo = address[netifaces.AF_LINK][0]
        mac = hwInfo['addr']
        ip = netInfo['addr']
        netMask = netInfo['netmask']
        cidr = netaddr.IPNetwork('%s/%s'% (ip, netMask))
        network = cidr.network
        print "\t", i, "\tMAC = ", mac, "\tIP = ", cidr

    # Removing the loopback interface from the list of interfaces to probe
    interfaces = [i for i in interfaces if i != 'lo' and i != 'lo0']

    for i in interfaces:
        print "----\nScanning on interface", i, "\n----\nResults:\n"
        netInfo = address[netifaces.AF_INET][0]

        cidr = str(netaddr.IPNetwork('%s/%s'% (netInfo['addr'],netInfo['netmask'])))
        ans,unans =srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=cidr),timeout=2)
        for s,r in ans:
            print "MAC: {0}\tIP: {1}".format(r.src, r.psrc)

if __name__ == "__main__":
    main()
#ans,unans=srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst="192.168.6.128/24"),timeout=2)
