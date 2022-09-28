#!/usr/bin/env python3

import fcntl
import socket, struct, random, os, argparse
import sys
import warnings

def _udpChecksum(data):
    #For now, just return the null checksum (i.e. "we didn't both calculating it")
    print("Checksumming %s" % data.hex())
    checksum = 0
    data_len = len(data)
    if (data_len % 2):
        data_len += 1
        data += struct.pack('!B', 0)
    
    for i in range(0, data_len, 2):
        w = (data[i] << 8) + (data[i + 1])
        checksum += w

    checksum = (checksum >> 16) + (checksum & 0xFFFF)
    checksum = ~checksum & 0xFFFF
    return checksum

def _ipChecksum(data):
    checksum = 0
    data_len = len(data)
    if (data_len % 2):
        data_len += 1
        data += struct.pack('!B', 0)
    
    for i in range(0, data_len, 2):
        w = (data[i] << 8) + (data[i + 1])
        checksum += w

    checksum = (checksum >> 16) + (checksum & 0xFFFF)
    checksum = ~checksum & 0xFFFF
    return checksum

#Test run:
#Source = 33676, Dest = 65535, Data = b"ping\n"
#Expected: 838cffff000dfe2070696e670a
#     Got: 838cffff000d957470696e670a
def _assembleUDPPacket(toSend, src, dest):
    srcIP, srcPort = src
    destIP, destPort = dest

    #Length. +8 is +4 for ports, +2 for this field, +2 for checksum.
    length = len(toSend) + 8

    #Need to assemble the pseudo-header for the checksum algorithm.
    srcPack = socket.inet_aton(srcIP)
    destPack = socket.inet_aton(destIP)

    pseudoHeader = srcPack + destPack
    pseudoHeader += struct.pack("!BBH", 0, 0x11, length)

    data = b""
    #Port information
    data += struct.pack("!H", srcPort)
    data += struct.pack("!H", destPort)
    
    data += struct.pack("!H", length)

    #Calculate the checksum. Checksum is set to zero because we don't know it.
    pseudoHeader += (data + bytes(2) + toSend)
    print(pseudoHeader.hex())
    checksum = _udpChecksum(pseudoHeader)
    data += struct.pack("!H", checksum)

    #Finally, append the data
    data += toSend
    return data

#Test:
#UDP(sP = 51653, dP = 65535, data = "ping\n")
#IP(src = localhost, dst = localhost)
#Expected: 45000021700d40004011ccbc7f0000017f000001c9c5ffff000dfe2070696e670a
#     Got: 45000021700d40004011ccbc7f0000017f000001c9c5ffff000dfe2070696e670a
def _assembleIPPacket(datagram, srcIP, destIP):
    #Values. See the wikipedia page for more info.
    VERSION = 0x4
    IHL = 0x5
    DSCP = 0x0
    ECN = 0x0
    length = len(datagram) + 20
    #Should probably be random, leaving it like this temporarily to check the checksum.
    identifier = random.randrange(1 << 16)
    FLAGS = 0x2
    FRAG_OFF = 0x0
    TTL = 64
    PROTOCOL = 0x11
    #Oh no not another checksum. please stop. Can't even worm my way out of this one.
    checksum = 0

    ipHeader = struct.pack("!2B3H2B", ((VERSION << 4) + IHL), ((DSCP << 2) + ECN), length, identifier, (FLAGS << 13) + FRAG_OFF, TTL, PROTOCOL)
    srcPack = socket.inet_aton(srcIP)
    destPack = socket.inet_aton(destIP)

    checkHeader = ipHeader + bytes(2) + srcPack + destPack
    #Same algorithm
    checksum = _ipChecksum(checkHeader)
    
    return ipHeader + struct.pack("!H", checksum) + srcPack + destPack + datagram

def _assemblePacket(data, src, dest):
    datagram = _assembleUDPPacket(data, src, dest)
    return _assembleIPPacket(datagram, src[0], dest[0])

#Magic value: 0x0800 = ETH_P_IP
ETH_P_IP = 0x0800

def createInterfaceSocket(interface):
    s = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(ETH_P_IP))
    s.bind((interface, ETH_P_IP))
    return (s, interface)

def sendData(interfaceSocket, data, src, dst, nextHopMAC):
    packet = _assemblePacket(data, src, dst)
    interfaceSocket[0].sendto(packet, (interfaceSocket[1], ETH_P_IP, 0, 0, nextHopMAC))

def closeInterfaceSocket(s):
    s[0].close()

def standalone():

    def verifyShort(s):
        sI = int(s)
        if sI < 0 or sI > 65535:
            raise ValueError("Port must be between 0 and 65535 (inclusive)")
        return sI

    def verifyIP(s):
        if s == 'localhost':
            return "127.0.0.1"
        else:
            try:
                socket.inet_aton(s)
                return s
            except OSError:
                raise ValueError("%s is not a valid IPv4 address!" % s)
    
    MTU = 1500
    def verifyMTU(s):
        sI = int(s)
        if sI < 1 or sI > MTU:
            warnings.warn("Weird and possibly broken MTU size of %i. Program may not work as expected." % sI)
        return sI

    def verifyMAC(s):
        macAddr = bytes.fromhex("".join(s.split(":")))
        if len(macAddr) != 6:
            raise ValueError("MAC address must be exactly 6 bytes long.")
        return macAddr

    VALID_INTERFACES = map(lambda k: k[1], socket.if_nameindex())
    def verifyInterface(s):
        if s in VALID_INTERFACES:
            return s
        raise ValueError("%s is not listed as a valid network interface! (%s)" % (s, ",".join(VALID_INTERFACES)))

    parser = argparse.ArgumentParser(description="Sends data from STDIN to the specified destination over UDP, spoofing the source IP address.")
    parser.add_argument("destIp", type=verifyIP, help="The IP address to send the UDP packets to.")
    parser.add_argument("destPort", type=verifyShort, help="The port to send the UDP packets to.")
    parser.add_argument("-sP", "--srcPort", type=verifyShort, help="The source port to spoof. If unspecified, one is generated at random.")
    parser.add_argument("-sI", "--srcIP", type=verifyIP, help="The source IP to spoof.")
    parser.add_argument("interface", type=verifyInterface, help="The network interface to use")
    parser.add_argument("-m", "--mtu", type=verifyMTU, default=MTU, help="Set the maximum amount of data in a single packet. Note that values greater than 1500 may not work.")
    parser.add_argument("-f", "--force-root", action="store_true", help="Attempt to open a raw socket, even if we don't appear to be root.")
    parser.add_argument("-a", "--mac-address", type=verifyMAC,default=bytes([255, 255, 255, 255, 255, 255]),help="The MAC address we want to send our packet to. This is usually the target's MAC, or the MAC of a router. If unspecified, uses broadcast MAC address.")

    args = parser.parse_args()

    if not args.force_root and os.geteuid() != 0:
        print("Sorry, you must be root to run this script.")
        quit()

    s = createInterfaceSocket(args.interface)

    #Some utter black magic from https://stackoverflow.com/questions/24196932/how-can-i-get-the-ip-address-from-a-nic-network-interface-controller-in-python
    def get_ip_address(ifname):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        return socket.inet_ntoa(fcntl.ioctl(
            s.fileno(),
            0x8915,  # SIOCGIFADDR
            struct.pack('256s', ifname.encode("utf-8")[:15])
        )[20:24])

    src = (args.srcIP or get_ip_address(args.interface), args.srcPort or random.randint(1024, 65535))
    dst = (args.destIp, args.destPort)

    try:
        while True:
            #Read a data block, ready to send.
            block = sys.stdin.buffer.read(args.mtu)
            if len(block) == 0:
                #End of file, terminate
                return
            else:
                sendData(s, block, src, dst, args.mac_address)
    finally:
        closeInterfaceSocket(s)
    

if __name__ == "__main__":
    standalone()
