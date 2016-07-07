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
   
    
    sta1 = net.addStation( 'sta1', ip='192.168.0.1/24' )
    sta2 = net.addStation( 'sta2', ip='192.168.0.2/24' )
    sta3 = net.addStation( 'sta3', ip='192.168.0.3/24' )
    sta4 = net.addStation( 'sta4', ip='192.168.0.4/24' )
    h1 = net.addHost('h0', ip='192.168.0.5')
    h2 = net.addHost('h1', ip='192.168.0.6')
       
    print "*** Adding Link"
    net.addLink(sta1, ap1, bw=10, loss=0)
    net.addLink(sta2, ap1, bw=10, loss=0)
    net.addLink(sta3, ap2, bw=10, loss=0)
    net.addLink(sta4, ap2, bw=10, loss=0)
    net.addLink(ap1, s0)
    net.addLink(ap2, s0)
    net.addLink(h1, s0)
    net.addLink(h2, s0)

    net.build()
    c0.start()
    c1.start()
                                 
                                 
    ap1.start( [c0] )
    ap2.start( [c0] )
    #nat0.start( [c0] )
    s0.start([c1])

    print "*** Running CLI"
    CLI( net )

    print "*** Stopping network"
    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    topology()
