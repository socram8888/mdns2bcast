#!/usr/bin/env python3

from socket import *
import fcntl
import sys
import struct
from random import randint

ETH_P_IP = 0x0800
ARPHRD_ETHER = 1
SIOCGIFADDR = 0x8915
SIOCGIFHWADDR = 0x8927

def ip_checksum(data):
	sum = 0

	# Calculate sum of entire words
	for i in range(len(data) // 2):
		sum += data[2 * i + 0] << 8
		sum += data[2 * i + 1]

	# Add trailing byte, if any
	if len(data) % 2 == 1:
		sum += data[-1] << 8

	# Remove carry
	while sum > 0xFFFF:
		sum = (sum & 0xFFFF) + (sum >> 16)

	return sum

if len(sys.argv) != 2:
	print(f'Usage: {sys.argv[0]} <interface>')
	sys.exit(1)

iface = sys.argv[1]

print(f'Binding to interface {iface}')

insrv = socket(AF_INET, SOCK_DGRAM)
insrv.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
insrv.setsockopt(SOL_SOCKET, SO_BINDTODEVICE, iface.encode() + b'\0')
mreq = struct.pack('4sl', inet_aton('224.0.0.251'), INADDR_ANY)
insrv.setsockopt(IPPROTO_IP, IP_ADD_MEMBERSHIP, mreq)
insrv.bind(('224.0.0.251', 5353))

outsrv = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_IP))
outsrv.bind((iface, 0))

print('Listening for packets now')

while True:
	query, addr = insrv.recvfrom(8192)

	# Run for queries only
	if (query[2] & 0x80) != 0:
		continue

	print(f'Relaying from {addr[0]}')

	packediface = struct.pack('256s', iface[:15].encode())
	ifaceip = fcntl.ioctl(insrv.fileno(), SIOCGIFADDR, packediface)[20:24]

	# Begin building packet

	udppacket = struct.pack(
		'>HHHH',
		# Source port
		5353,
		# Destination port
		5353,
		# UDP packet length (including header)
		8 + len(query),
		# Checksum (to be calculated),
		0x0000
	) + query

	pseudoheader = struct.pack(
		'>4s4sxBH',
		# Source IPv4
		ifaceip,
		# Destination IPv4
		b'\xE0\x00\x00\xFB',
		# Protocol (UDP)
		17,
		# UDP length
		len(udppacket)
	)

	udpsum = ip_checksum(pseudoheader + udppacket) ^ 0xFFFF
	if udpsum == 0:
		udpsum = 0xFFFF

	udppacket = bytearray(udppacket)
	udppacket[6] = udpsum >> 8
	udppacket[7] = udpsum & 0xFF

	ipheader = bytearray(struct.pack(
		'>BBHHHBBH4s4s',
		# Version (4) and IHL (5 32-bit words)
		0x45,
		# DSCP and ECN (both 0)
		0x00,
		# Total packet length
		20 + len(udppacket),
		# Packet ID
		randint(0x0000, 0xFFFF),
		# Flags and fragment offset
		0,
		# TTL
		64,
		# Protocol (UDP)
		17,
		# Checksum (to be calculated)
		0x0000,
		# Source address
		ifaceip,
		# Destination address (224.0.0.251)
		b'\xE0\x00\x00\xFB'
	))

	ipsum = ip_checksum(ipheader) ^ 0xFFFF

	packet = bytearray(ipheader)
	packet[10] = ipsum >> 8
	packet[11] = ipsum & 0xFF
	packet.extend(udppacket)

	# Destination
	dest = (
		# Interface
		iface,
		# EtherType
		ETH_P_IP,
		# Packet type
		PACKET_BROADCAST,
		# ARP type
		ARPHRD_ETHER,
		# Destination MAC
		b'\xFF\xFF\xFF\xFF\xFF\xFF'
	)

	outsrv.sendto(packet, dest)
