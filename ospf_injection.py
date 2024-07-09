from scapy.all import *
from scapy.contrib.ospf import *
import threading
import time
import struct
import socket

OSPF_PORT = 89
OSPF_MULTICAST_ADDRESS = "224.0.0.5"  # All OSPF routers
OSPF_MULTICAST_MAC = "01:00:5e:00:00:05"

class OSPF_Hello_Message(object):
    def _init_(self, router_id='1.1.1.1', area_id='0.0.0.0', mask='255.255.255.0'):
        self.router_id = router_id
        self.area_id = area_id
        self.mask = mask

    def render(self):
        try:
            hello = OSPF_Hello(
                mask=self.mask,
                hellointerval=10,  # Interval between Hello packets
                options=0x02,  # OSPF options field as a hexadecimal bitmask
                router=self.router_id,
                backup='0.0.0.0',
                neighbors=[]
            )

            ospf = OSPF_Hdr(
                src=self.router_id,
                area=self.area_id,
                type=1,
                authdata=0,
            )


            return ospf / hello

        except Exception as e:
            print(f"Error constructing OSPF Hello packet: {e}")
            return None

def get_multicast_mac(ip):
    try:
        # Convert multicast IP address to MAC address
        n = struct.unpack("!I", socket.inet_aton(ip))[0]
        mac = "01:00:5e:%02x:%02x:%02x" % ((n >> 16) & 0x7f, (n >> 8) & 0xff, n & 0xff)
        return mac
    except Exception as e:
        print(f"Error converting IP to MAC: {e}")
        return None

def send_ospf_hello():
    try:
        print("Sending OSPF Hello packets to multicast address", OSPF_MULTICAST_ADDRESS)
        iface = "eth0"  # Change this to the appropriate interface if needed
        ospf_multicast_mac = get_multicast_mac(OSPF_MULTICAST_ADDRESS)

        while True:
            ospf_hello_message = OSPF_Hello_Message()
            ospf_packet = ospf_hello_message.render()

            if ospf_packet is None:
                print("Failed to construct OSPF packet. Exiting.")
                break

            # Craft IP packet
            ip_packet = IP(dst=OSPF_MULTICAST_ADDRESS, proto=OSPF_PORT) / ospf_packet

            # Craft Ethernet packet
            ether_packet = Ether(dst=ospf_multicast_mac) / ip_packet

            # Print packet information before sending
            print("\nSending OSPF Hello packet:")
            print(ether_packet.summary())
            print(ether_packet.show())
            print("--------")

            # Send the packet
            sendp(ether_packet, iface=iface, verbose=False)

            time.sleep(15)  # Wait for 15 seconds before sending the next OSPF Hello packet

    except KeyboardInterrupt:
        print("\nExiting program...")
    except Exception as e:
        print(f"Error in send_ospf_hello: {e}")

if _name_ == "_main_":
    send_ospf_thread = threading.Thread(target=send_ospf_hello)
    send_ospf_thread.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nExiting program...")
        send_ospf_thread.join()