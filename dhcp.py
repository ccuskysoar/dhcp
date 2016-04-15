import argparse,socket
import struct
from uuid import getnode as get_mac
from random import randint

MAX_BYTES = 65535


def getMacInBytes():
    mac = str(hex(get_mac()))
    mac = mac[2:]
    while len(mac) < 12 :
        mac = '0' + mac
    macb = b''
    for i in range(0, 12, 2) :
        m = int(mac[i:i + 2], 16)
        macb += struct.pack('!B', m)
    return macb

def DHCPDiscover():
    # random a transaction ID
    transactionID = b''
    for i in range(4):
            t = randint(0, 255)
            transactionID += struct.pack('!B', t)
 
    #build the packet
    macb = getMacInBytes()
    packet = b''
    packet += b'\x01'   #Message type: Boot Request (1)
    packet += b'\x01'   #Hardware type: Ethernet
    packet += b'\x06'   #Hardware address length: 6
    packet += b'\x00'   #Hops: 0 
    packet += transactionID       #Transaction ID
    packet += b'\x00\x00'    #Seconds elapsed: 0
    packet += b'\x80\x00'   #Bootp flags: 0x8000 (Broadcast) + reserved flags
    packet += b'\x00\x00\x00\x00'   #Client IP address: 0.0.0.0
    packet += b'\x00\x00\x00\x00'   #Your (client) IP address: 0.0.0.0
    packet += b'\x00\x00\x00\x00'   #Next server IP address: 0.0.0.0
    packet += b'\x00\x00\x00\x00'   #Relay agent IP address: 0.0.0.0
    #packet += b'\x00\x26\x9e\x04\x1e\x9b'   #Client MAC address: 00:26:9e:04:1e:9b
    packet += macb
    packet += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'   #Client hardware address padding: 00000000000000000000
    packet += b'\x00' * 67  #Server host name not given
    packet += b'\x00' * 125 #Boot file name not given
    packet += b'\x63\x82\x53\x63'   #Magic cookie: DHCP
    packet += b'\x35\x01\x01'   #Option: (t=53,l=1) DHCP Message Type = DHCP Discover
    #packet += b'\x3d\x06\x00\x26\x9e\x04\x1e\x9b'   #Option: (t=61,l=6) Client identifier
    packet += b'\x3d\x06' + macb
    packet += b'\x37\x03\x03\x01\x06'   #Option: (t=55,l=3) Parameter Request List
    packet += b'\xff'   #End Option
    return packet

def DHCPOffer(discover_packet):
    
    #build the packet
    macb = getMacInBytes()
    packet = b''
    packet += b'\x02'   #Message type: Boot Request (1)
    packet += b'\x01'   #Hardware type: Ethernet
    packet += b'\x06'   #Hardware address length: 6
    packet += b'\x00'   #Hops: 0 
    packet += discover_packet[4:8]       #Transaction ID
    packet += b'\x00\x00'    #Seconds elapsed: 0
    packet += b'\x80\x00'   #Bootp flags: 0x8000 (Broadcast) + reserved flags
    packet += b'\x00\x00\x00\x00'   #Client IP address: 0.0.0.0
    packet += b'\xc0\xa8\x2c\x8f'   #Your (client) IP address: 192.168.44.143
    packet += b'\xc0\xa8\x2c\x8d'   #Next server IP address: 192.168.44.141
    packet += b'\x00\x00\x00\x00'   #Relay agent IP address: 0.0.0.0
    #packet += b'\x00\x26\x9e\x04\x1e\x9b'   #Client MAC address: 00:26:9e:04:1e:9b
    packet += macb
    packet += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'   #Client hardware address padding: 00000000000000000000
    packet += b'\x00' * 64  #Server host name not given
    packet += b'\x00' * 128 #Boot file name not given
    packet += b'\x63\x82\x53\x63'   #Magic cookie: DHCP
    packet += b'\x35\x01\x02'   #Option: (t=53,l=1) DHCP Message Type = DHCP Offer
    #packet += b'\x3d\x06\x00\x26\x9e\x04\x1e\x9b'   #Option: (t=61,l=6) Client identifier
    #packet += b'\x3d\x06' + macb
    packet += b'\x36\x04\xc0\xa8\x2c\x8d' #Option: (t=54,l=4 Server Identifier 192.168.44.141)
    packet += b'\x33\x04\x00\x00\x07\x08' #Option: (t=51,l=4 IP Address Lease Time)
    packet += b'\x03\x04\xc0\xa8\x2c\x02' #Option: (t=3,l=4 Router 192.168.44.2)
    packet += b'\x01\x04\xff\xff\xff\x00' #Option: (t=1 ,l=4 Subnet Mask 255.255.255.0)
    packet += b'\x06\x04\xc0\xa8\x2c\x02' #Option: (t=6 ,l=4 Domain Name Server 192.168.44.2)
    #packet += b'\x37\x03\x03\x01\x06'   #Option: (t=55,l=3) Parameter Request List
    packet += b'\xff'   #End Option
    packet += b'\x00' * 26
    return packet

def DHCPRequest():
    # random a transaction ID
    transactionID = b''
    for i in range(4):
            t = randint(0, 255)
            transactionID += struct.pack('!B', t)

    #build the packet
    macb = getMacInBytes()
    packet = b''
    packet += b'\x01'   #Message type: Boot Request (1)
    packet += b'\x01'   #Hardware type: Ethernet
    packet += b'\x06'   #Hardware address length: 6
    packet += b'\x00'   #Hops: 0 
    packet += transactionID       #Transaction ID
    packet += b'\x00\x00'    #Seconds elapsed: 0
    packet += b'\x80\x00'   #Bootp flags: 0x8000 (Broadcast) + reserved flags
    packet += b'\x00\x00\x00\x00'   #Client IP address: 0.0.0.0
    packet += b'\x00\x00\x00\x00'   #Your (client) IP address: 0.0.0.0
    packet += b'\x00\x00\x00\x00'   #Next server IP address: 0.0.0.0
    packet += b'\x00\x00\x00\x00'   #Relay agent IP address: 0.0.0.0
    #packet += b'\x00\x26\x9e\x04\x1e\x9b'   #Client MAC address: 00:26:9e:04:1e:9b
    packet += macb
    packet += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'   #Client hardware address padding: 00000000000000000000
    packet += b'\x00' * 67  #Server host name not given
    packet += b'\x00' * 125 #Boot file name not given
    packet += b'\x63\x82\x53\x63'   #Magic cookie: DHCP
    packet += b'\x35\x01\x03'   #Option: (t=53,l=3) DHCP Message Type = DHCP Request
    packet += b'\x32\x04\xc0\xa8\x2c\x8f' #Option: (t=54,l=4 Requested 192.168.44.143)
    packet += b'\x36\x04\xc0\xa8\x2c\x8d' #Option: (t=54,l=4 DHCP Server 192.168.44.141)
    packet += b'\xff'   #End Option
    return packet

def DHCPAck(request_packet):

    #build the packet
    macb = getMacInBytes()
    packet = b''
    packet += b'\x02'   #Message type: Boot Request (1)
    packet += b'\x01'   #Hardware type: Ethernet
    packet += b'\x06'   #Hardware address length: 6
    packet += b'\x00'   #Hops: 0 
    packet += request_packet[4:8]       #Transaction ID
    packet += b'\x00\x00'    #Seconds elapsed: 0
    packet += b'\x80\x00'   #Bootp flags: 0x8000 (Broadcast) + reserved flags
    packet += b'\x00\x00\x00\x00'   #Client IP address: 0.0.0.0
    packet += b'\xc0\xa8\x2c\x8f'   #Your (client) IP address: 192.168.44.143
    packet += b'\xc0\xa8\x2c\x8d'   #Next server IP address: 192.168.44.141
    packet += b'\x00\x00\x00\x00'   #Relay agent IP address: 0.0.0.0
    #packet += b'\x00\x26\x9e\x04\x1e\x9b'   #Client MAC address: 00:26:9e:04:1e:9b
    packet += macb
    packet += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'   #Client hardware address padding: 00000000000000000000
    packet += b'\x00' * 64  #Server host name not given
    packet += b'\x00' * 128 #Boot file name not given
    packet += b'\x63\x82\x53\x63'   #Magic cookie: DHCP
    packet += b'\x35\x01\x05'   #Option: (t=53,l=1) DHCP Message Type = DHCP Offer
    #packet += b'\x3d\x06\x00\x26\x9e\x04\x1e\x9b'   #Option: (t=61,l=6) Client identifier
    #packet += b'\x3d\x06' + macb
    packet += b'\x36\x04\xc0\xa8\x2c\x8d' #Option: (t=54,l=4 Server Identifier 192.168.44.141)
    packet += b'\x33\x04\x00\x00\x07\x08' #Option: (t=51,l=4 IP Address Lease Time)
    packet += b'\x03\x04\xc0\xa8\x2c\x02' #Option: (t=3,l=4 Router 192.168.44.2)
    packet += b'\x01\x04\xff\xff\xff\x00' #Option: (t=1 ,l=4 Subnet Mask 255.255.255.0)
    packet += b'\x06\x04\xc0\xa8\x2c\x02' #Option: (t=6 ,l=4 Domain Name Server 192.168.44.2)
    #packet += b'\x37\x03\x03\x01\x06'   #Option: (t=55,l=3) Parameter Request List
    packet += b'\xff'   #End Option
    return packet




def server():
        sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1) #broadcast
        sock.bind(('0.0.0.0', 67))
        print('Lestening at {}'.format(sock.getsockname()))
        while True:
                discover_packet,address = sock.recvfrom(MAX_BYTES)
                print(discover_packet)
                #sock.sendto(DHCPOffer(discover_packet), address)
                sock.sendto(DHCPOffer(discover_packet), ('255.255.255.255',68))
                #print(address)
                request_packet,address = sock.recvfrom(MAX_BYTES)
                print(request_packet)
                sock.sendto(DHCPAck(request_packet), ('255.255.255.255', 68))
                #sock.close()

def client():
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1) #broadcast
        try:
            sock.bind(('0.0.0.0', 68))    #we want to send from port 68a
            print('Lestening at {}'.format(sock.getsockname()))
        except Exception as e:
            print('port 68 in use...')
            sock.close()
            input('press any key to quit...')
            exit()
        sock.sendto(DHCPDiscover(), ('255.255.255.255', 67))
        #while True:
        offer_packet,address = sock.recvfrom(MAX_BYTES)
        print(offer_packet)
        #print(address)
           # if address!=()
        sock.sendto(DHCPRequest(), ('255.255.255.255', 67))
        ack_packet,address = sock.recvfrom(MAX_BYTES)
        print(ack_packet)

if __name__ == '__main__':
        choices = {'client': client,'server': server}
        parser = argparse.ArgumentParser(description='Send and receive UDP locally')
        parser.add_argument('role', choices=choices, help='which role to play')
        parser.add_argument('-p', metavar='PORT', type=int, default=1060, help='UDP port (default 1060)')
        args = parser.parse_args()
        function = choices[args.role]
        function()

