#!/usr/bin/python

# This script will connect from the local host (lhost) to a remote host (rhost) on a
# remote port (rport) and attempt to identify the service there

from random import randint
from scapy.all import TCP, IP, send, TCP_SERVICES, sr1


def main(rhost, rport):
    """
    Completes the three way handshake, the determines
    what service is available on that port, if any
    """

    try:
        rport = int(rport)

    except ValueError:
        print("{} does not appear to be a valid number.".format(rport))
        print("Please change the destination port value and try again.")
        return

    source_port = randint(1024, 65535)
  
    # Packet[1] SYN
    ip = IP(dst=rhost, ttl=128, len=48)
    tcp = TCP(sport=source_port, dport=rport, flags='S',
              options=[('MSS', 1460), ('NOP', ()), ('NOP', ()), ('SAckOK', '')])
    syn = ip/tcp

    # Packet[2] SYN-ACK
    syn_ack = sr1(syn)
    replyflag = syn_ack.sprintf("%TCP.flags%")
    print ("Received TCP Reply flag {}".format(replyflag))

    # Packet[3] ACK
    if(replyflag == 'SA'):
        SEQ=syn_ack[TCP].ack
        ACK=syn_ack[TCP].seq + 1
        source_port = syn_ack.dport ## The OS may change source_port
        tcp = TCP(dport=rport, flags = 'A', seq=SEQ, ack=ACK, sport=source_port)
        send(ip/tcp)

    # Equivalent to the C language function getservbyport()
    TCP_REVERSE = dict((TCP_SERVICES[k], k) for k in TCP_SERVICES.keys())
    print("Port {} is {}".format(rport, TCP_REVERSE[rport]))

if __name__ == "__main__":
    remote_ip = raw_input("What is the remote IP ? ")
    remote_port = raw_input("What is the remote port? ")
    main(remote_ip, remote_port)