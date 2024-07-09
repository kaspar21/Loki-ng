import struct
import threading
import time
import tkinter as tk
from tkinter import ttk
from scapy.all import *

RIP_VERSION = 2
RIP_PORT = 520
RIP_MULTICAST_ADDRESS = "224.0.0.9"
RIP_MULTICAST_MAC = "01:00:5e:00:00:09"

class rip_message(object):
    COMMAND_REQUEST = 1
    COMMAND_RESPONSE = 2
    
    def __init__(self, command=None, entries=None):
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

    def __init__(self, af=None, tag=None, addr=None, mask=None, nh=None, metric=None):
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

    def __init__(self, type=None, data=None):
        self.type = type
        self.data = data

    def render(self):
        return struct.pack("!HH16s", 0xffff, self.type, self.data)

    def parse(self, data):
        (self.type, self.data) = struct.unpack("!xxH16s", data[:20])
        return data[20:]

class rip_thread(threading.Thread):
    def __init__(self, parent):
        threading.Thread.__init__(self)
        self.running = True
        self.parent = parent

    def run(self):
        print("RIP: Thread started")
        timer = 15
        while self.running:
            if timer == 15:
                timer = 0
                rlist = []
                for ip in self.parent.routes:
                    (ip, mask, nh, metrik) = self.parent.routes[ip]
                    rlist.append(rip_entry(rip_entry.AF_INET, 0, inet_aton(ip), inet_aton(mask), inet_aton(nh), int(metrik)))
                msg = rip_message(rip_message.COMMAND_RESPONSE, rlist)
                data = msg.render()
                for dst in self.parent.hosts:
                    pkt = Ether(dst=RIP_MULTICAST_MAC, src=self.parent.mac) / \
                          IP(src=self.parent.ip, dst=RIP_MULTICAST_ADDRESS, ttl=2) / \
                          UDP(sport=RIP_PORT, dport=RIP_PORT) / \
                          data
                    sendp(pkt, iface=self.parent.iface)
            timer = timer + 1
            time.sleep(1)
        print("RIP: Thread terminated")

    def shutdown(self):
        self.running = False

class mod_class(object):
    HOST_IP_ROW = 0

    ROUTE_IP_ROW = 0
    ROUTE_MASK_ROW = 1
    ROUTE_NEXT_HOP_ROW = 2
    ROUTE_METRIC_ROW = 3
    
    def __init__(self, parent, platform):
        self.parent = parent
        self.platform = platform
        self.name = "rip"
        self.group = "ROUTING"

    def start_mod(self):
        self.thread = rip_thread(self)
        self.thread.start()  # Start the RIP thread
        sniff(filter="udp and port 520", prn=self.process_packet, store=0)

    def shut_mod(self):
        self.thread.shutdown()  # Shutdown the RIP thread
        self.thread.join()

    def create_ui(self):
        root = tk.Tk()
        root.title("RIP Module")

        # Hosts section
        host_frame = ttk.Frame(root, padding="10")
        host_frame.pack(fill=tk.BOTH, expand=True)
        host_label = ttk.Label(host_frame, text="Host IP:")
        host_label.grid(row=0, column=0, padx=5, pady=5)
        self.host_ip_entry = ttk.Entry(host_frame, width=20)
        self.host_ip_entry.grid(row=0, column=1, padx=5, pady=5)
        add_host_button = ttk.Button(host_frame, text="Add Host", command=self.on_add_host_clicked)
        add_host_button.grid(row=0, column=2, padx=5, pady=5)
        self.host_treeview = ttk.Treeview(host_frame, columns=("Host IP",), show="headings")
        self.host_treeview.heading("Host IP", text="Host IP")
        self.host_treeview.grid(row=1, column=0, columnspan=3, padx=5, pady=5)

        # Routes section
        route_frame = ttk.Frame(root, padding="10")
        route_frame.pack(fill=tk.BOTH, expand=True)
        route_label_ip = ttk.Label(route_frame, text="IP:")
        route_label_ip.grid(row=0, column=0, padx=5, pady=5)
        route_label_mask = ttk.Label(route_frame, text="Mask:")
        route_label_mask.grid(row=0, column=1, padx=5, pady=5)
        route_label_nh = ttk.Label(route_frame, text="Next Hop:")
        route_label_nh.grid(row=0, column=2, padx=5, pady=5)
        route_label_metric = ttk.Label(route_frame, text="Metric:")
        route_label_metric.grid(row=0, column=3, padx=5, pady=5)
        self.route_ip_entry = ttk.Entry(route_frame, width=15)
        self.route_ip_entry.grid(row=1, column=0, padx=5, pady=5)
        self.route_mask_entry = ttk.Entry(route_frame, width=15)
        self.route_mask_entry.grid(row=1, column=1, padx=5, pady=5)
        self.route_nh_entry = ttk.Entry(route_frame, width=15)
        self.route_nh_entry.grid(row=1, column=2, padx=5, pady=5)
        self.route_metric_entry = ttk.Entry(route_frame, width=10)
        self.route_metric_entry.grid(row=1, column=3, padx=5, pady=5)
        add_route_button = ttk.Button(route_frame, text="Add Route", command=self.on_add_route_clicked)
        add_route_button.grid(row=1, column=4, padx=5, pady=5)
        self.route_treeview = ttk.Treeview(route_frame, columns=("IP", "Mask", "Next Hop", "Metric"), show="headings")
        self.route_treeview.heading("IP", text="IP")
        self.route_treeview.heading("Mask", text="Mask")
        self.route_treeview.heading("Next Hop", text="Next Hop")
        self.route_treeview.heading("Metric", text="Metric")
        self.route_treeview.grid(row=2, column=0, columnspan=5, padx=5, pady=5)

        return root

    def on_add_host_clicked(self):
        host_ip = self.host_ip_entry.get()
        if host_ip:
            self.hosts[host_ip] = None
            self.host_treeview.insert("", tk.END, values=(host_ip,))
            self.host_ip_entry.delete(0, tk.END)

    def on_add_route_clicked(self):
        ip = self.route_ip_entry.get()
        mask = self.route_mask_entry.get()
        nh = self.route_nh_entry.get()
        metric = self.route_metric_entry.get()
        if ip and mask and nh and metric:
            self.routes[ip] = (ip, mask, nh, metric)
            self.route_treeview.insert("", tk.END, values=(ip, mask, nh, metric))
            self.route_ip_entry.delete(0, tk.END)
            self.route_mask_entry.delete(0, tk.END)
            self.route_nh_entry.delete(0, tk.END)
            self.route_metric_entry.delete(0, tk.END)

    def process_packet(self, pkt):
        if RIP in pkt:
            rip_pkt = pkt[RIP]
            # Process RIP packet here
            pass

if __name__ == '__main__':
    mod = mod_class(None, None)  # Initialize mod_class instance
    mod.start_mod()  # Start the RIP thread
    root = mod.create_ui()
    root.mainloop()
    mod.shut_mod()  # Ensure RIP thread is properly shutdown
