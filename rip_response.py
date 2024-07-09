from scapy.all import *
import struct
import threading
import time

RIP_VERSION = 2
RIP_PORT = 520
RIP_MULTICAST_ADDRESS = "224.0.0.9"
RIP_MULTICAST_MAC = "01:00:5e:00:00:09"

class rip_message(object):
    COMMAND_REQUEST = 1
    COMMAND_RESPONSE = 2

    def _init_(self, command=None, entries=None):
        self.command = command
        if not entries:
            self.entries = []
        else:
            self.entries = entries

    def render(self):
        data = struct.pack("!BBxx", self.command, RIP_VERSION)
        for i in self.entries:
            data += i.render()
        return data

    def parse(self, data):
        (self.command,) = struct.unpack("!Bxxx", data[:4])
        left = data[4:]
        while left:
            (af,) = struct.unpack("!H", left[:2])
            if af == 0xffff:
                entry = rip_auth()
            else:
                entry = rip_entry()
            left = entry.parse(left)
            self.entries.append(entry)

class rip_entry(object):
    AF_INET = 2

    def _init_(self, af=None, tag=None, addr=None, mask=None, nh=None, metric=None):
        self.af = af
        self.tag = tag
        self.addr = addr
        self.mask = mask
        self.nh = nh
        self.metric = metric

    def render(self):
        return struct.pack("!HH", self.af, self.tag) + self.addr + self.mask + self.nh + struct.pack("!I", self.metric)

    def parse(self, data):
        (self.af, self.tag) = struct.unpack("!HH", data[:4])
        self.addr = data[4:8]
        self.mask = data[8:12]
        self.nh = data[12:16]
        (self.metric, ) = struct.unpack("!I", data[16:20])
        return data[20:]

class rip_auth(object):
    AUTH_SIMPLE = 2

    def _init_(self, type=None, data=None):
        self.type = type
        self.data = data

    def render(self):
        return struct.pack("!HH16s", 0xffff, self.type, self.data)

    def parse(self, data):
        (self.type, self.data) = struct.unpack("!xxH16s", data[:20])
        return data[20:]

def get_multicast_mac(ip):
    # Convert multicast IP address to MAC address
    n = struct.unpack("!I", socket.inet_aton(ip))[0]
    mac = "01:00:5e:%02x:%02x:%02x" % ((n >> 16) & 0x7f, (n >> 8) & 0xff, n & 0xff)
    return mac

def send_rip_response():
    print("Sending RIP responses to multicast address", RIP_MULTICAST_ADDRESS)
    iface = "eth0"  # Change this to the appropriate interface if needed
    rip_multicast_mac = get_multicast_mac(RIP_MULTICAST_ADDRESS)

    while True:
        rlist = []  # List of RIP entries (modify and append entries here if needed)
        msg = rip_message(rip_message.COMMAND_RESPONSE, rlist)
        data = msg.render()

        # Craft UDP packet
        udp_packet = UDP(sport=RIP_PORT, dport=RIP_PORT) / Raw(load=data)

        # Craft IP packet
        ip_packet = IP(dst=RIP_MULTICAST_ADDRESS) / udp_packet

        # Craft Ethernet packet
        ether_packet = Ether(dst=rip_multicast_mac) / ip_packet

        # Print packet information before sending
        print("\nSending RIP packet:")
        print(ether_packet.summary())
        print(ether_packet.show())
        print("--------")
        # Send the packet
        sendp(ether_packet, iface=iface, verbose=False)

        time.sleep(15)  # Wait for 15 seconds before sending the next RIP response

if _name_ == "_main_":
    send_rip_response_thread = threading.Thread(target=send_rip_response)
    send_rip_response_thread.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nExiting program...")
        send_rip_response_thread.join()