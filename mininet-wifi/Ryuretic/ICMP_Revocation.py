#####################################################################
# Ryuretic: A Modular Framework for RYU        					 	#
# !/mininet/examples/SecFrameTest/ICMP_Revocation.py				#
# Author:														   	#
#   Jacob Cox (jcox70@gatech.edu)								   	#
# ICMP_Revocation.py												#
# date 12 May 2016												  	#
#####################################################################
# Copyright (C) 2016 Jacob Cox - All Rights Reserved				#
# You may use, distribute and modify this code under the			#
# terms of the Ryuretic license, provided this work is cited		#
# in the work for which it is used.								 	#
# For latest updates, please visit:								 	#
#				   https://github.gatech.edu/jcox70/SecRevFrame    	#
#####################################################################
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
CNTRL_ADDR = '192.168.0.40'

def checksum(str):
	csum, count = 0, 0
	countTo = (len(str) / 2) * 2
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

def revoke_policy(keyID):
	print "Sending message"
	cntrlIP = CNTRL_ADDR
	ping(cntrlIP,'d,'+keyID)
	
def provide_result(keyID,match):
	print "Sending message"
	cntrlIP = CNTRL_ADDR
	ping(cntrlIP,'r,'+keyID+','+match)

while True:
	try:
		#tbl = open("/var/www/cgi-bin/RevTable.txt").readlines()
		tbl = open("/var/www/cgi-bin/RapTable.txt").readlines()
		# Receives keyID and match result
		for line in range(len(tbl)):
			if line != '\n':
				#keyID = tbl[line].rstrip(' \t\r\n\0')
				tbl_line = tbl[line].rstrip(' \t\r\n\0')
				data = tbl_line.split(',')
				keyID, match = data[0], data[1]
				print len(keyID), ' : ', keyID
				#revoke_policy(keyID)
				provide_result(keyID,match)
		#tbl = open("/var/www/cgi-bin/RevTable.txt",'w')
		tbl = open("/var/www/cgi-bin/RapTable.txt",'w')
		tbl.close()
	except ValueError:
		#print ValueError
		print "Attempt failed. Trying again."

	time.sleep(30)