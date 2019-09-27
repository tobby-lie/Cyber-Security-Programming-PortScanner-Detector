import threading
import socket
import time
import struct
import queue

# Last modified: 9/26/19 @ 6:47PM

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
    threshold = 301.

    #while current_time < threshold:
    while True:
        print(current_time)
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
        keys = [k for k, v in dict.items() if (current_time - v) > 300.]
        for x in keys:
            del dict[x]
        if current_time > threshold:
            threshold  += threshold
            temp_dict = dict.copy()
            t2 = threading.Thread(target=fanout_rate, args=(temp_dict,))
            t2.start()
            #current_time = 0.
        #print(dict)
    return

@storeInQueue
def fanout_rate(dict):

    '''t2 = threading.Thread(target=portscanner_detector(), args = ())
    t2.start()'''
    #dict = portscanner_detector()

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

    y_dict = {}
    z_dict = {}
    d_dict = {}

    '''dict = {}

    connection_tuple = ('192.168.10.145', '192.168.10.138', '1')
    dict[connection_tuple] = 1.2
    connection_tuple = ('192.168.10.145', '192.168.10.138', '2')
    dict[connection_tuple] = 1.2
    connection_tuple = ('192.168.10.145', '192.168.10.138', '3')
    dict[connection_tuple] = 1.2
    connection_tuple = ('192.168.10.145', '192.168.10.138', '4')
    dict[connection_tuple] = 1.2
    connection_tuple = ('192.168.10.145', '192.168.10.138', '5')
    dict[connection_tuple] = 1.2
    connection_tuple = ('192.168.10.145', '192.168.10.138', '6')
    dict[connection_tuple] = 1.2

    connection_tuple = ('192.168.10.144', '192.168.10.138', '1')
    dict[connection_tuple] = 1.3
    connection_tuple = ('192.168.10.144', '192.168.10.138', '2')
    dict[connection_tuple] = 1.4
    connection_tuple = ('192.168.10.144', '192.168.10.138', '3')
    dict[connection_tuple] = 1.5
    connection_tuple = ('192.168.10.144', '192.168.10.138', '4')
    dict[connection_tuple] = 1.1
    connection_tuple = ('192.168.10.144', '192.168.10.138', '5')
    dict[connection_tuple] = 1.2
    connection_tuple = ('192.168.10.144', '192.168.10.138', '6')
    dict[connection_tuple] = 1.2
    connection_tuple = ('192.168.10.144', '192.168.10.138', '7')
    dict[connection_tuple] = 1.6
    connection_tuple = ('192.168.10.144', '192.168.10.138', '8')
    dict[connection_tuple] = 1.7'''

    #print(dict)

    while current_time < 301.:
        # second
        source_sec = {}
        for key, value in dict.items():
            if (value < current_time) and (value > current_time - second_increment):
                sec_fanouts += 1
                if key[0] in source_sec:
                    source_sec[key[0]] += 1
                else:
                    source_sec[key[0]] = 1
                y = {k:v for (k,v) in source_sec.items() if v > 5}
                if y:
                    for key, val in y.items():
                        y_dict[key] = val
        # minute
        if current_time % 60. == 0:
            source_min = {}
            for key, value in dict.items():
                if (value < current_time) and (value > current_time - minute_increment):
                    min_fanouts += 1
                    if key[0] in source_min:
                        source_min[key[0]] += 1
                    else:
                        source_min[key[0]] = 1
                    z = {k:v for (k,v) in source_min.items() if v > 100}
                    if z:
                        for key, val in z.items():
                            z_dict[key] = val
        # five minutes
        if current_time % 300. == 0:
            source_fivemin = {}
            for key, value in dict.items():
                if (value < current_time) and (value > current_time - fiveminute_increment):
                    fivemin_fanouts += 1
                    if key[0] in source_fivemin:
                        source_fivemin[key[0]] += 1
                    else:
                        source_fivemin[key[0]] = 1
                    d = {k:v for (k,v) in source_fivemin.items() if v > 300}
                    if d:
                        for key, val in d.items():
                            d_dict[key] = val

        # exceeds 5 per second
        #   WILL NEED TO MAKE YET ANOTHER SET OF DICTS TO HOLD ALL KEY VALUE
        #   PAIRS THAT FIT THESE CRITERIA
        if y_dict:
            for key, val in y_dict.items():
                print("--------------------------------------------------------")
                print("port scanner detected on source IP: " + str(key))
                print("avg. fan-out per sec: " + str(source_sec[key]/60.) + ", avg fan-out per min: " + str(source_min[key]/1.))
                #print("fan-out per 5min: " + str(source_fivemin[key]))
                print("\n reason: fan-out rate per sec = " + str(source_sec[key]) + " (must be less than 5).")
                print("--------------------------------------------------------")
        # exceeds 100 per minute
        if z_dict:
            for key, val in z_dict.items():
                print("--------------------------------------------------------")
                print("port scanner detected on source IP: " + str(key))
                print("avg. fan-out per sec: " + str(source_sec[key]/60.) + ", avg fan-out per min: " + str(source_min[key]/1.))
                #print("fan-out per 5min: " + str(source_fivemin[key]))
                print("\n reason: fan-out rate per min= " + str(source_min[key]) + " (must be less than 100).")
                print("--------------------------------------------------------")
        # exceeds 300 per 5 minutes
        if d_dict:
            for key, val in d_dict.items():
                print("--------------------------------------------------------")
                print("port scanner detected on source IP: " + str(key))
                print("avg. fan-out per sec: " + str(source_sec[key]/60.) + ", avg fan-out per min: " + str(source_min[key]/1.))
                #print("fan-out per 5min: " + str(source_fivemin[key]))
                print("\n reason: fan-out rate per five min = " + str(source_fivemin[key]) + " (must be less than 300).")
                print("--------------------------------------------------------")
        current_time += 1
    #print(y_dict)
    return

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

t1 = threading.Thread(target=portscanner_detector, args=())
t1.start()

'''t1 = threading.Thread(target=fanout_rate, args = ())
t1.start()

y_dict, z_dict, d_dict, sec_fanouts, min_fanouts, fivemin_fanouts, source_sec, source_min, source_fivemin = my_queue.get()'''
#print(min_fanouts)
#y_list, z_list, d_list, sec_fanouts, min_fanouts, fivemin_fanouts = fanout_rate()
