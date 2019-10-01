# Tobby Lie

import threading
import socket
import time
import struct
import queue

# Last modified: 10/1/19 @ 4:11PM

# queue used to hold values to be returned from a thread
my_queue = queue.Queue()

def storeInQueue(f):
    ''' utilized to contain values to be returned from thread if there are return values '''
    def wrapper(*args):
        my_queue.put(f(*args))
    return wrapper

def portscanner_detector():

    # get packets
    packets = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))

    # empty dict to hold connections
    dict = {}

    # start time is current time in seconds
    start_time = time.time()
    # set current time to zero
    current_time = 0
    # 300 seconds is 5 minutes
    # every time threshold is reached, dict is checked for fan-out
    threshold_sec = 1.
    threshold_min = 60.
    threshold_fivemin = 300.

    while True:
        # get ethernet_data and address from packets
        ethernet_data, address = packets.recvfrom(65536)
        # get destination mac, source mac, protocol and ip_data
        dest_mac, src_mac, protocol, ip_data = ethernet_dissect(ethernet_data)

        # ipv4
        if protocol == 8:
            ip_protocol, src_ip, dest_ip, transport_data = ipv4_dissect(ip_data)
            # tcp
            if ip_protocol == 6:
                # get source and destination ports
                src_port, dest_port = tcp_dissect(transport_data)
                # tuple for source ip, destination ip and destination port
                connection_tuple = (src_ip, dest_ip, dest_port)
                # time of connection is current time - start time
                timestamp = (time.time() - start_time)
                dict[connection_tuple] = timestamp
        # current time is time minus start time
        current_time = time.time() - start_time
        # check dict for all keys that have connection times that have elapsed over 5 minutes
        temp_dict = dict.copy()
        t = threading.Thread(target=keys_for_delete, args=(temp_dict, current_time, ))
        t.start()
        keys = my_queue.get()
        # delete all elements that have existed for more than 5 minutes
        for x in keys:
            del dict[x]
        # if current time has gone past threshold which is 5 minutes in our case
        # then check for fan-out for second, minute and five minute
        # increase threshold by itself in order to continue this pattern
        if current_time > threshold_sec:
            # print current time and size of dict just as a way to monitor progress
            print("current time: " + str(current_time))
            print("size of dict: " + str(len(dict)))
            # increment threshold_sec in order to continue checking every second
            threshold_sec += 1.
            # use a copy as to not alter the original dict in use
            temp_dict = dict.copy()
            # start separate thread in order to get fan out results for sec
            t2 = threading.Thread(target=fanout_rate_sec, args=(temp_dict,(current_time-1.0),(current_time)))
            t2.start()
        if current_time > threshold_min:
            # print current time and size of dict just as a way to monitor progress
            print("current time: " + str(current_time))
            print("size of dict: " + str(len(dict)))
            # increment threshold_min in order to continue checking every minute
            threshold_min += 60.0
            # use a copy as to not alter the original dict in use
            temp_dict = dict.copy()
            # start separate thread in order to get fan out results for min
            t3 = threading.Thread(target=fanout_rate_min, args=(temp_dict,(current_time-60.0),(current_time)))
            t3.start()
        if current_time > threshold_fivemin:
            # print current time and size of dict just as a way to monitor progress
            print("current time: " + str(current_time))
            print("size of dict: " + str(len(dict)))
            # increment threshold_fivemin in order to continue checking every five minutes
            threshold_fivemin  += 300.
            # use a copy as to not alter the original dict in use
            temp_dict = dict.copy()
            # start separate thread in order to get fan out results for fivemin
            t4 = threading.Thread(target=fanout_rate_fivemin, args=(temp_dict,(current_time-300.0),(current_time)))
            t4.start()

@storeInQueue
def keys_for_delete(dict, current_time):
    ''' stored in queue to return thread return values
        returns keys to be deleted that are over 5 minutes
    '''
    keys = [k for k, v in dict.items() if abs(current_time - v) > 300.]
    return keys

def fanout_rate_sec(dict, start, end):
    ''' prints out fan out calculations for each second that passes '''

    # for all source ips that have connections that indicate portscanner
    y_dict = {}

    # dict to hold amount of times connections are made in this interval for every
    # source ip
    source_sec = {}

    for key, value in dict.items():
        # check all dict elements that fall under one second in one second
        # increments
        if (value < end) and (value > start):
            # increment number of connections made with source ip within second
            # interval
            if key[0] in source_sec:
                source_sec[key[0]] += 1
            else:
                source_sec[key[0]] = 1
            # if connections is more than 5 per second, then record
            y = {k:v for (k,v) in source_sec.items() if v > 5}
            if y:
                for key, val in y.items():
                    y_dict[key] = val
    # exceeds 5 per second
    if y_dict:
        for key, val in y_dict.items():
            print("--------------------------------------------------------")
            print("port scanner detected on source IP: " + str(key))
            print("avg. fan-out per sec: " + str(source_sec[key]))
            print("\n reason: fan-out rate per sec = " + str(source_sec[key]) + " (must be less than 5).")
            print("--------------------------------------------------------")
        delete = [k for k, v in  y_dict.items() if k == key]
        for key in delete:
            del y_dict[key]

def fanout_rate_min(dict, start, end):
    ''' prints out fan out calculations for each minute that passes '''

    # for all source ips that have connections that indicate portscanner
    z_dict = {}

    # dict to hold number of connections for each minute per source ip
    source_min = {}

    for key, value in dict.items():
        # check all dict elements that fall under one minute in one minute
        # increments
        if (value < end) and (value > start):
            # increment number of connections made with source ip within minute
            # interval
            if key[0] in source_min:
                source_min[key[0]] += 1
            else:
                source_min[key[0]] = 1
            # if connections is more than 100 per minute, then record
            z = {k:v for (k,v) in source_min.items() if v > 100.}
            if z:
                for key, val in z.items():
                    z_dict[key] = val
    # exceeds 100 per minute
    if z_dict:
        for key, val in z_dict.items():
            print("--------------------------------------------------------")
            print("port scanner detected on source IP: " + str(key))
            print("avg. fan-out per sec: " + str(source_min[key]/60.) + ", avg fan-out per min: " + str(source_min[key]/1.))
            print("\n reason: fan-out rate per min= " + str(source_min[key]) + " (must be less than 100).")
            print("--------------------------------------------------------")
        delete = [k for k, v in  z_dict.items() if k == key]
        for key in delete:
            del z_dict[key]

def fanout_rate_fivemin(dict, start, end):
    ''' prints out fan out calculations for each five minutes that pass '''

    # for all source ips that have connections that indicate portscanner
    d_dict = {}

    # dict to hold number of connections each five minutes per source ip
    source_fivemin = {}

    for key, value in dict.items():
        # check all dict elements that fall under five minutes in five minute
        # increments
        if (value < end) and (value > start):
            # increment number of connections made with source ip within five
            # minute interval
            if key[0] in source_fivemin:
                source_fivemin[key[0]] += 1
            else:
                source_fivemin[key[0]] = 1
            # if connections is more than 300 per five minutes, then record
            d = {k:v for (k,v) in source_fivemin.items() if v > 300}
            if d:
                for key, val in d.items():
                    d_dict[key] = val
    # exceeds 300 per 5 minutes
    if d_dict:
        for key, val in d_dict.items():
            print("--------------------------------------------------------")
            print("port scanner detected on source IP: " + str(key))
            print("avg. fan-out per sec: " + str(source_fivemin[key]/300.) + ", avg fan-out per min: " + str(source_fivemin[key]/5.))
            print("fan-out per 5min: " + str(source_fivemin[key]))
            print("\n reason: fan-out rate per five min = " + str(source_fivemin[key]) + " (must be less than 300).")
            print("--------------------------------------------------------")
        delete = [k for k, v in  d_dict.items() if k == key]
        for key in delete:
            del d_dict[key]

def tcp_dissect(transport_data):
    ''' extract source and destination port from transport data '''
    # it is the first four bytes, first 2 are source and second 2 are destination
    source_port, dest_port = struct.unpack('!HH', transport_data[:4])
    return source_port, dest_port

def ethernet_dissect(ethernet_data):
    ''' extract dest mac, source mac, protocol '''
    dest_mac, src_mac, protocol = struct.unpack('!6s6sH', ethernet_data[:14])
    return mac_format(dest_mac), mac_format(src_mac), socket.htons(protocol), ethernet_data[14:]

def mac_format(mac):
    ''' format mac address '''
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

# start a thread for storing connections made
t1 = threading.Thread(target=portscanner_detector, args=())
t1.start()
