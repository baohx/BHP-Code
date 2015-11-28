import socket
import os
import struct
import threading

from netaddr import IPNetwork,IPAddress
from ctypes import *

def hexdump(src, length=16):
    result = []
    digits = 4 if isinstance(src, unicode) else 2

    for i in xrange(0, len(src), length):
       s = src[i:i+length]
       hexa = b' '.join(["%0*X" % (digits, ord(x))  for x in s])
       text = b''.join([x if 0x20 <= ord(x) < 0x7F else b'.'  for x in s])
       result.append( b"%04X   %-*s   %s" % (i, length*(digits + 1), hexa, text) )

    print b'\n'.join(result)

# host to listen on
host   = "192.168.1.9"

# subnet to target
subnet = "192.168.1.0/24"

# magic we'll check ICMP responses for
magic_message = "PYTHONRULES!"

def udp_sender(subnet,magic_message):
    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    for ip in IPNetwork(subnet):
        try:
            sender.sendto(magic_message,("%s" % ip,65212))
        except:
            pass
        
                
class IP(Structure):
    
    _fields_ = [
        ("ihl",           c_ubyte, 4),
        ("version",       c_ubyte, 4),
        ("tos",           c_ubyte),
        ("len",           c_ushort),
        ("id",            c_ushort),
        ("offset",        c_ushort),
        ("ttl",           c_ubyte),
        ("protocol_num",  c_ubyte),
        ("sum",           c_ushort),
        #("src",           c_ulong),
        #("dst",           c_ulong)
        ("src",           c_uint32),
        ("dst",           c_uint32)
    ]
    
    def __new__(self, socket_buffer=None):
            return self.from_buffer_copy(socket_buffer)    
        
    def __init__(self, socket_buffer=None):

        # map protocol constants to their names
        self.protocol_map = {1:"ICMP", 6:"TCP", 17:"UDP"}
        
        # human readable IP addresses
        #self.src_address = socket.inet_ntoa(struct.pack("<L",self.src))
        #self.dst_address = socket.inet_ntoa(struct.pack("<L",self.dst))
        self.src_address = socket.inet_ntoa(struct.pack("@I",self.src))
        self.dst_address = socket.inet_ntoa(struct.pack("@I",self.dst))
    
        # human readable protocol
        try:
            self.protocol = self.protocol_map[self.protocol_num]
        except:
            self.protocol = str(self.protocol_num)
            


class ICMP(Structure):
    
    _fields_ = [
        ("type",         c_ubyte),
        ("code",         c_ubyte),
        ("checksum",     c_ushort),
        ("unused",       c_ushort),
        ("next_hop_mtu", c_ushort)
        ]
    
    def __new__(self, socket_buffer):
        return self.from_buffer_copy(socket_buffer)    

    def __init__(self, socket_buffer):
        pass

# create a raw socket and bind it to the public interface
if os.name == "nt":
    socket_protocol = socket.IPPROTO_IP 
else:
    socket_protocol = socket.IPPROTO_ICMP
    
sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)

sniffer.bind((host, 0))

# we want the IP headers included in the capture
sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

# if we're on Windows we need to send some ioctls
# to setup promiscuous mode
if os.name == "nt":
    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)


# start sending packets
t = threading.Thread(target=udp_sender,args=(subnet,magic_message))
t.start()        

try:
    while True:
        
        # read in a single packet
        raw_buffer = sniffer.recvfrom(65535)[0]
        
        # create an IP header from the first 20 bytes of the buffer
        ip_header = IP(raw_buffer[0:20])
        print "ip_header=>"
        hexdump(raw_buffer[0:20]) 
        print "1 |> Protocol: %s %s -> %s" % (ip_header.protocol, ip_header.src_address, ip_header.dst_address)
    
        # if it's ICMP we want it
        if ip_header.protocol == "ICMP":
            
            # calculate where our ICMP packet starts
            offset = ip_header.ihl * 4
            print "2 |> offset=>",offset," ICMP size=>",sizeof(ICMP)
            hexdump(raw_buffer[offset:offset+sizeof(ICMP)])
            buf = raw_buffer[offset:offset + sizeof(ICMP)]
            print "2'|> After ICMP=>"
            hexdump(raw_buffer[offset + sizeof(ICMP) + 20:])
            # create our ICMP structure
            icmp_header = ICMP(buf)
            
            print "3 |> ICMP -> Type: %d Code: %d" % (icmp_header.type, icmp_header.code)

            # now check for the TYPE 3 and CODE 3 which indicates
            # a host is up but no port available to talk to           
            if icmp_header.code == 3 and icmp_header.type == 3:
                
                # check to make sure we are receiving the response 
                # that lands in our subnet
                if IPAddress(ip_header.src_address) in IPNetwork(subnet):
                    
                    # test for our magic message
                    print '4 |> raw_buffer=>'
                    hexdump(raw_buffer)
                    if raw_buffer[len(raw_buffer)-len(magic_message):] == magic_message:
                        print "Host Up: %s" % ip_header.src_address
# handle CTRL-C
except KeyboardInterrupt:
    # if we're on Windows turn off promiscuous mode
    if os.name == "nt":
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)

