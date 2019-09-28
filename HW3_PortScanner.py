# Tobby Lie

import socket
import time

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

def udp_scanner(port):
    ''' try-except block to ensure we don't throw any errors if issues arise'''
    ''' here we attempt to connect to target ip and its port'''
    try:
        ''' if successful connection return True '''
        udp_sock.connect((target, port))
        return True
    except:
        ''' if unsuccessful return False '''
        return False

# try first 1024 port numbers
def tcp_scan(time_interval):
    count = 0
    for portNumber in range(1, 4096):
        print(count)
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

# try first 1024 port numbers
'''for portNumber in range(1, 1024):
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # if connection to portNumber is successful
    # print out that port is open
    if udp_scanner(portNumber):
        print('[*]Port', portNumber, '/udp', 'is open')
    udp_sock.close()'''
while True:
    tcp_scan(1.0)
