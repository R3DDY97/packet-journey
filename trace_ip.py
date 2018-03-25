#!/usr/bin/env python3
'''traceroute in python3'''

import os
import socket
import time
from struct import pack
from itertools import count

TIME_OUT, ICMP, UDP = pack("ll", 2, 0), socket.IPPROTO_ICMP, socket.IPPROTO_UDP
host, port, TTL = "", 33434, count(1)

def udp_socket(current_ttl):
    '''returns UDP socket to send packets'''
    udp_sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM, proto=UDP)
    udp_sock.setsockopt(socket.SOL_IP, socket.IP_TTL, current_ttl)
    return udp_sock


def icmp_socket():
    '''returns ICMP socket to receive info from router/destination_ip'''
    icmp_sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_RAW, proto=ICMP)
    icmp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVTIMEO, TIME_OUT)
    icmp_sock.bind((host, port))
    return icmp_sock

def destination_ip(dest):
    '''Returns destionation ip from hostname'''
    try:
        dest_ip = socket.gethostbyname(dest)
    except socket.error as err:
        # print(err.strerror)
        # raise SystemExit
        os.sys.exit()
    return dest_ip

def trace_routemap(dest_ip):
    '''traces the hosts while packet travels to destination'''
    while True:
        current_ttl = next(TTL)
        udp_sock = udp_socket(current_ttl)
        sent_time = time.time()
        udp_sock.sendto(b" ", (dest_ip, port))

        icmp_sock = icmp_socket()
        sender_hostname, sender_ip, received_time = icmp_sender(icmp_sock)
        udp_sock.close()
        icmp_sock.close()

        if sender_ip:
            round_trip = "{:.3}".format(received_time - sent_time)
            print("{:*^4} {}-({}) in {} ms\n".format(
                current_ttl, sender_hostname, sender_ip, round_trip))
        else:
            print("{:*^4} ".format(current_ttl))

        if sender_ip == dest_ip or current_ttl > 30:
            break


def icmp_sender(icmp_sock):
    '''recieve icmp packets sent and return sender hostname, ip and recieved time'''
    try:
        _, sender_addr = icmp_sock.recvfrom(1024)
        received_time = time.time()
    except socket.error as err:
        # print(err.strerror)
        return None, None, None
    try:
        sender_hostname = socket.gethostbyaddr(sender_addr[0])[0]
    except socket.error as err:
        sender_hostname = "Unknown hostname"
    return sender_hostname, sender_addr[0], received_time


def main():
    '''returns trace route of destination host'''
    if os.getuid() != 0:
        print("\nNeed to run as R00T to create ICMP socket in tracing route\n")
        os.sys.exit()
    try:
        destination = os.sys.argv[1]
    except IndexError:
        print("\nNeed to pass hostname or host ip as first argument\n")
        os.sys.exit()
    dest_ip = destination_ip(destination)
    trace_routemap(dest_ip)



if __name__ == '__main__':
    os.system("clear||cls")
    main()
