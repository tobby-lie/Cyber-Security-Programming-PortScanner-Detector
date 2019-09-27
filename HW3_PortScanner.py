# Tobby Lie

import socket
import time

# updated 9/26/19 @ 6:48PM

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
count = 0
for portNumber in range(1, 1024):
    print(count)
    time.sleep(1)
    tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # if connection to portNumber is successful
    # print out that port is open
    if tcp_scanner(portNumber):
        print('[*]Port', portNumber, '/tcp', 'is open')
    tcp_sock.close()
    count += 1

# try first 1024 port numbers
'''for portNumber in range(1, 1024):
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # if connection to portNumber is successful
    # print out that port is open
    if udp_scanner(portNumber):
        print('[*]Port', portNumber, '/udp', 'is open')
    udp_sock.close()'''
