# Tobby Lie

import socket
import time

# last updated: 10/4/19 @ 4:06PM

# make a socket instance for tcp and pass it 2 parameters
# AF_INET is the address family ipv4
# SOCK_STREAM means connection oriented TCP protocol
tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# make a socket instance for udp and pass it 2 parameters
# AF_INET is the address family ipv4
# SOCK_STREAM means connection oriented UDP protocol
udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# target ip we will use to connect
target = input("[+] Enter Target IP:")

def tcp_scanner(port):
    ''' try-except block to ensure we don't throw any errors if issues arise'''
    ''' here we attempt to connect to target ip and its port'''
    try:
        ''' if successful connection return True '''
        tcp_sock.connect((target, port))
        return True
    except:
        ''' if unsuccessful return False '''
        return False

# try first 1024 port numbers
def tcp_scan(time_interval):
    # keep count of which port is being scanned
    count = 0
    # 65535 tcp ports
    for portNumber in range(1, 65535):
        print(count)
        # wait between every 2 consecutive connections
        if count % 2 == 0:
            tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # if connection to portNumber is successful
            # print out that port is open
            if tcp_scanner(portNumber):
                print('[*]Port', portNumber, '/tcp', 'is open')
            tcp_sock.close()
        else:
            time.sleep(time_interval)
        count += 1

# get time interval from user for wait time to respect
time_interval = input("Time interval in seconds: ")
# keep scanning
while True:
    tcp_scan(float(time_interval))
