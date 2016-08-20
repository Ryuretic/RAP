#####################################################################
# Ryuretic: A Modular Framework for RYU                             #
# !/mininet-wifi/Ryuretic/ICMP_Send.py                              #
# Author:                                                           #
#   Jacob Cox (jcox70@gatech.edu)                                   #                             #
# ICMP_Send.py                                                      #
# date 25 April 2016                                                #
#####################################################################
# Copyright (C) 2016 Jacob Cox - All Rights Reserved                #
# You may use, distribute and modify this code under the            #
# terms of the Ryuretic license, provided this work is cited        #
# in the work for which it is used.                                 #
# For latest updates, please visit:                                 #
#                   https://github.com/Ryuretic/RAP                 #
#####################################################################
"""
This file is initiated to create ICMP packets used to signal the controller.
It's primary function is to initiate comms with the controller. For testing,
it can also send delete requests to the controller. Use this program in
conjuction with ICMP_Listen.py on the same host (i.e., trusted agent). 
"""

#ref: http://www.binarytides.com/raw-socket-programming-in-python-linux/
# run this on host
from socket import *
import os
import sys
import struct
import time
import select
import binascii
import socket

ICMP_ECHO_REQUEST = 8
ICMP_ECHO_REPLY = 0
packageSent = 0;

def checksum(str):
    csum = 0
    countTo = (len(str) / 2) * 2
    count = 0
    while count < countTo:
        thisVal = ord(str[count+1]) * 256 + ord(str[count])
        csum = csum + thisVal
        csum = csum & 0xffffffffL
        count = count + 2
    if countTo < len(str):
        csum = csum + ord(str[len(str) - 1])
        csum = csum & 0xffffffffL
    csum = (csum >> 16) + (csum & 0xffff)
    csum = csum + (csum >> 16)
    answer = ~csum
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer

def sendOneICMP(mySocket, destAddr, ID, com='ABCDefgh'):
    global packageSent
    myChecksum = 0

    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, ID, 1)
    data = struct.pack("8s", com)
    myChecksum = checksum(header + data)

    myChecksum = socket.htons(myChecksum)

    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, ID, 1)
    packet = header+data

    mySocket.sendto(packet, (destAddr, 1))
    packageSent += 1
    
def sendICMP(destAddr, com):
    icmp = socket.getprotobyname("icmp")
    print "ICMP Protocol: ", icmp

    try:
        mySocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
    except socket.error, (errno, msg):
        if errno == 1:
            raise socket.error(msg)

    myID = os.getpid() & 0xFFFF
    sendOneICMP(mySocket, destAddr, myID, com)

def ping(hostIP,com):
    print "Sending ICMP message to ", hostIP, "."
    sendICMP(hostIP, com)

while(1):
    choice = raw_input("Enter:\n 1) to initialize \n 2) to send revocation \n ")
    print "You entered: ", choice
    cntrlIP = '192.168.0.40'
    if int(choice) == 1: 
        ping(cntrlIP, 'i,0')
    elif int(choice) == 2:
        keyID = raw_input("Enter key ID:  ")
        ping(cntrlIP,'d,'+keyID)
    else:
        "Try again"
