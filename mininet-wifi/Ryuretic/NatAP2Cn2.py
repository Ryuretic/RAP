#!/usr/bin/python

"""
This example shows how to work with both wireless and wired medium
"""

from mininet.net import Mininet
from mininet.node import  Controller, OVSKernelSwitch, RemoteController
from mininet.node import OVSSwitch, UserSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.link import TCLink
from mininet.nodelib import NAT
from mininet.topo import Topo

def topology():
    "Create a network."
    net = Mininet( link=TCLink, switch=OVSSwitch )
    c0 = Controller( 'c0', port=6634 )
    c1 = RemoteController( 'c1', ip='127.0.0.1', port=6633 )
    net.addController(c0)
    net.addController(c1) 

    
    print "*** Creating nodes"
    s0 = net.addSwitch('s0')
    ap1 = net.addBaseStation( 'ap1', ssid="ssid_ap1", mode="g", channel="5" )
    ap2 = net.addBaseStation( 'ap2', ssid="ssid_ap2", mode="g", channel="1" )
   
    
    sta1 = net.addStation( 'sta1', ip='192.168.0.1/24', defaultRoute='via 192.168.0.224' )
    sta2 = net.addStation( 'sta2', ip='192.168.0.2/24', defaultRoute='via 192.168.0.224' )
    sta3 = net.addStation( 'sta3', ip='192.168.0.3/24', defaultRoute='via 192.168.0.224' )
    sta4 = net.addStation( 'sta4', ip='192.168.0.4/24', defaultRoute='via 192.168.0.224' )
    h1 = net.addHost('h1', ip='192.168.0.5', defaultRoute='via 192.168.0.224')
    h2 = net.addHost('h2', ip='192.168.0.6', defaultRoute='via 192.168.0.224')

    
       
    print "*** Adding Link"
    net.addLink(sta1, ap1, bw=10, loss=0)
    net.addLink(sta2, ap1, bw=10, loss=0)
    net.addLink(sta3, ap2, bw=10, loss=0)
    net.addLink(sta4, ap2, bw=10, loss=0)
    net.addLink(ap1, s0)
    net.addLink(ap2, s0)
    net.addLink(h1, s0)
    net.addLink(h2, s0)

    ##############################################################
    #nat = net.addNAT('nat', ip=natIP, inNamespace=False)
    nat = net.addHost( 'nat', cls=NAT, ip='192.168.0.224', subnet='192.168.0.0/24', inNamespace=False)
    net.addLink(nat, s0)
    ##############################################################

    
##    s2 = net.addSwitch('s2')
##    nat1=net.addHost('nat1', cls=NAT, ip='192.168.0.220',
##                                  subnet='10.0.0.0/24',
##                                  inetIntf='nat1-eth0', localIntf='nat1-eth1',
##                                  **hostConfig)
##    net.addLink(nat1, s0)
##    natParams = {'ip' : '10.0.0.1/24'}
##    net.addLink(s2, nat1, intfName1='nat1-eth1', params1=natParams)
##
##    h3 = net.addHost('h3', ip='10.0.0.2', defaultRoute = 'via 10.0.0.1')
##    h4 = net.addHost('h4', ip='10.0.0.3', defaultRoute = 'via 10.0.0.1')
##    h5 = net.addHost('h5', ip='10.0.0.4', defaultRoute = 'via 10.0.0.1')
##    net.addLink(h3, s2)
##    net.addLink(h4, s2)
##    net.addLink(h5, s2)
    
        
    net.build()
    c0.start()
    c1.start()
                                 
                                 
    ap1.start( [c0] )
    ap2.start( [c0] )
    s0.start([c1])

    print "*** Running CLI"
    CLI( net )

    print "*** Stopping network"
    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    topology()
