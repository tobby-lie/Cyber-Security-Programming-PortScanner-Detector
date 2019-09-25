import threading
import socket
import time
import struct
import queue

# Last modified: 9/25/19 @ 4:29PM

my_queue = queue.Queue()

def storeInQueue(f):
    def wrapper(*args):
        my_queue.put(f(*args))
    return wrapper

def portscanner_detector():

    packets = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))

    dict = {}

    start_time = time.time()
    current_time = 0
    # 300 seconds is 5 minutes
    threshold = 60.

    while current_time < threshold:
        print(current_time)
    #while True:
        ethernet_data, address = packets.recvfrom(65536)
        dest_mac, src_mac, protocol, ip_data = ethernet_dissect(ethernet_data)

        if protocol == 8:
            ip_protocol, src_ip, dest_ip, transport_data = ipv4_dissect(ip_data)
            if ip_protocol == 6:
                src_port, dest_port = tcp_dissect(transport_data)

                connection_tuple = (src_ip, dest_ip, dest_port)
                timestamp = (time.time() - start_time)
                dict[connection_tuple] = timestamp

        current_time = time.time() - start_time
        keys = [k for k, v in dict.items() if (current_time - v) > threshold]
        for x in keys:
            del dict[x]
    return dict

@storeInQueue
def fanout_rate():
    dict = portscanner_detector()

    second_increment = 1.
    minute_increment = 60.
    fiveminute_increment = 300.

    current_time = 0
    source_sec = {}
    source_min = {}
    source_fivemin = {}

    sec_fanouts = 0
    min_fanouts = 0
    fivemin_fanouts = 0

    y_list = []
    z_list = []
    d_list = []

    while current_time < 300.:
        # second
        for key, value in dict.items():
            if (value < current_time) and (value > current_time - second_increment):
                sec_fanouts += 1
                if key in source_sec:
                    source_sec[key] += 1
                else:
                    source_sec[key] = 1
                y = {k:v for (k,v) in source_sec.items() if v > 5}
                y_list.append(y)
        # minute
        if current_time % 60 == 0:
            for key, value in dict.items():
                if (value < current_time) and (value > current_time - minute_increment):
                    min_fanouts += 1
                    if key in source_min:
                        source_min[key] += 1
                    else:
                        source_min[key] = 1
                    z = {k:v for (k,v) in source_min.items() if v > 100}
                    z_list.append(z)
        # five minutes
        if current_time % 300 == 0:
            for key, value in dict.items():
                if (value < current_time) and (value > current_time - fiveminute_increment):
                    fivemin_fanouts += 1
                    if key in source_fivemin:
                        source_fivemin[key] += 1
                    else:
                        source_fivemin[key] = 1
                    d = {k:v for (k,v) in source_fivemin.items() if v > 300}
                    d_list.append(d)
        current_time += 1

    return y_list, z_list, d_list, sec_fanouts, min_fanouts, fivemin_fanouts
   #print(dict)

def tcp_dissect(transport_data):
    ''' extract source and destination port from transport data '''
    # it is the first four bytes, first 2 are source and second 2 are destination
    source_port, dest_port = struct.unpack('!HH', transport_data[:4])
    return source_port, dest_port

def ethernet_dissect(ethernet_data):
    dest_mac, src_mac, protocol = struct.unpack('!6s6sH', ethernet_data[:14])
    return mac_format(dest_mac), mac_format(src_mac), socket.htons(protocol), ethernet_data[14:]

def mac_format(mac):
    mac = map('{:02x}'.format, mac)
    return ':'.join(mac).upper()

def ipv4_format(address):
    ''' convert each element to string by applying map '''
    return '.'.join(map(str, address))

def ipv4_dissect(ip_data):
    ''' extracts data needed from ip_data '''
    # skip first 9 bytes, take in 1 byte for protocol
    # skip next 2 bytes, 4 bytes for source address
    # 4 bytes for destination address
    # the rest is ip data
    ip_protocol, source_ip, target_ip = struct.unpack('!9xB2x4s4s', ip_data[:20])
    return ip_protocol, ipv4_format(source_ip), ipv4_format(target_ip), ip_data[20:]

t1 = threading.Thread(target=fanout_rate, args = ())
t1.start()

y_list, z_list, d_list, sec_fanouts, min_fanouts, fivemin_fanouts = my_queue.get()
print(y_list)
#y_list, z_list, d_list, sec_fanouts, min_fanouts, fivemin_fanouts = fanout_rate()
