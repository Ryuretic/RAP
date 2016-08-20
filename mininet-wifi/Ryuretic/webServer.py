#################################################################################
# Trusted Agent Web Server                                                      #
# Author: Jacob Cox (jcox70@ece.gatech.edu)                                     #
# webServer.py save to /mininet-wifi/Ryuretic/webServer.py                      #
# Date: 4 May 2016 ###############################################################################

###################################################################
##                     Requirements
###################################################################
"""
1) install lighttpd web server
    a) sudo apt-get install lighttpd
2) modify the lighttpd.conf file with following:
    a) cd /etc/lighttpd
    b) edit /etc/lighttpd/lighttpd.conf
       see https://github.com/Ryuretic/RAP/wiki/Lighttpd.conf-file    
3) setup index.php
    a. cd /var/www
    b. touch index.php (if it doesn't exist already
    c. edit file
       see https://github.com/Ryuretic/RAP/wiki/Index.php
"""
######################################################################

import sys
from subprocess import call
import os

def turnOnWebServer():
    os.system('/etc/init.d/lighttpd start')

def stopWebServer():
    os.system('/etc/init.d/lighttpd stop')

def enableIPForwarding():
    #Common command to enable IP forwarding on linux systems
    os.system('echo 1 > /proc/sys/net/ipv4/ip_forward')

def setWebPage(interface, attackIP):
    #Iptable code (minor changes) comes from:
    #https://blogs.oracle.com/ksplice/entry/hijacking_http_traffic_on_your
    os.system('iptables -t nat --flush')
    os.system('iptables --zero')
    os.system('iptables -A FORWARD --in-interface %s -j ACCEPT' %interface)
    os.system('iptables -t nat --append POSTROUTING --out-interface '\
          'h1-eth0 -j MASQUERADE')
    os.system('iptables -t nat -A PREROUTING -p tcp --dport 80 '\
          '--jump DNAT --to-destination %s' %attackIP)

def killWebServer(attackIP):
    os.system('sudo iptables -t nat -D PREROUTING -p tcp --dport ' \
              '80 -j NETMAP --to %s' %attackIP)
    print "removing ip tables"
    os.system('iptables --table nat --flush')
    stopWebServer()

def renderWeb(interface, attackIP):
    turnOnWebServer()
    enableIPForwarding()
    setWebPage(interface, attackIP)

def getVectors():
    #use ifconfig on h1 to verify interface and IP
    interface = 'h1-eth0'
    yourIP='192.168.0.1' #raw_input('Enter Your IP Address: ')
    return interface, yourIP

def main():
    #nmap()
    os.system('hostname -I')
    print "Your IP address is: "
    print "Starting Web Server"
    choice = raw_input('1) Start Web Server or 2) Stop \n')   

    if choice == '1':
        interface, serverIP = getVectors()
        renderWeb(interface, serverIP)
    elif choice == '2':
        serverIP = '192.168.0.1' #raw_input("Enter your IP")
        killWebServer(serverIP)
        print "don't forget netstat -tulp  and kill process"
    else:
        print "wrong value"
     

main()
