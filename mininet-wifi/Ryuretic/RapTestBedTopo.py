#!/usr/bin/python

"""
This example shows how to work with both wireless and wired medium

cd mininet-wifi
sudo python Ryuretic/RapTestBedTopo.py
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
    #create local controller for APs
    c0 = Controller( 'c0', port=6634 )
    #create controller for s0 (Ryuretic)
    c1 = RemoteController( 'c1', ip='127.0.0.1', port=6633 )
    net.addController(c0)
    net.addController(c1)
    
    print "*** Creating nodes"
    s0 = net.addSwitch('s0')
        ##################    Create Rogue APs    ############################### 
    ap1 = net.addBaseStation( 'ap1', ssid="ssid_ap1", channel="1", mode="g",
                              range='20' )
    ap3 = net.addBaseStation( 'ap3', ssid="ssid_ap3", mode="g", channel="6",
                              range='20')
    
    ################   Create Rogue Stations   #############################
    sta1 = net.addStation( 'sta1', ip='192.168.0.11/24', mac='AA:BB:BB:BB:BB:01',
                           defaultRoute='via 192.168.0.224' )
    sta2 = net.addStation( 'sta2', ip='192.168.0.12/24', mac='AA:BB:BB:BB:BB:02',
                           defaultRoute='via 192.168.0.224' )
    sta3 = net.addStation( 'sta3', ip='192.168.0.13/24', mac='AA:BB:BB:BB:BB:03',
                           defaultRoute='via 192.168.0.224' )
    sta4 = net.addStation( 'sta4', ip='10.0.0.1/24', mac='AA:BB:BB:BB:BB:11',
                           defaultRoute='via 10.0.0.22' )
    sta5 = net.addStation( 'sta5', ip='10.0.0.2/24', mac='AA:BB:BB:BB:BB:12',
                           defaultRoute='via 10.0.0.22' )
    sta6 = net.addStation( 'sta6', ip='10.0.0.3/24', mac='AA:BB:BB:BB:BB:13',
                           defaultRoute='via 10.0.0.22' )
    
    ##################    Create Hosts    ####################################
    h1 = net.addHost('h1', ip='192.168.0.1', mac='AA:AA:AA:AA:AA:01',
                     defaultRoute='via 192.168.0.224')
    h2 = net.addHost('h2', ip='192.168.0.2', mac='AA:AA:AA:AA:AA:02',
                     defaultRoute='via 192.168.0.224')
    h3 = net.addHost('h3', ip='192.168.0.3', mac='AA:AA:AA:AA:AA:03',
                     defaultRoute='via 192.168.0.224')
    h4 = net.addHost('h4', ip='192.168.0.4', mac='AA:AA:AA:AA:AA:04',
                     defaultRoute='via 192.168.0.224')
    h5 = net.addHost('h5', ip='192.168.0.5', mac='AA:AA:AA:AA:AA:05',
                     defaultRoute='via 192.168.0.224')
    h6 = net.addHost('h6', ip='192.168.0.6', mac='AA:AA:AA:AA:AA:06',
                     defaultRoute='via 192.168.0.224')
    ##################   Wireless AP Interface   #############################

    print "*** Adding Link"
    wl_bw = 15
    wl_delay = '5ms'
    wl_loss = 10
    
    net.addLink(ap1, sta1, bw=wl_bw, loss=wl_loss, delay=wl_delay )
    net.addLink(ap1, sta2, bw=wl_bw, loss=wl_loss, delay=wl_delay )
    net.addLink(ap1, sta3, bw=wl_bw, loss=wl_loss, delay=wl_delay )
    #####################    NAT1 Interface    ###############################   
    net.addLink(ap3, sta4, bw=wl_bw, loss=wl_loss, delay=wl_delay )
    net.addLink(ap3, sta5, bw=wl_bw, loss=wl_loss, delay=wl_delay )
    net.addLink(ap3, sta6, bw=wl_bw, loss=wl_loss, delay=wl_delay )
    #####################   Link devices to Switch    ######################## 
    w_delay='3ms'
    
    net.addLink(ap1, s0, bw=15, delay=w_delay)
    net.addLink(h1, s0, bw=15, delay=w_delay)
    net.addLink(h2, s0, bw=15, delay=w_delay)
    net.addLink(h3, s0, bw=15, delay=w_delay)
    net.addLink(h4, s0, bw=15, delay=w_delay)
    net.addLink(h5, s0, bw=15, delay=w_delay)
    net.addLink(h6, s0, bw=15, delay=w_delay)
    ######################   Create NAT for Internet   #######################
    nat = net.addHost( 'nat', cls=NAT, ip='192.168.0.224', mac='AA:AA:AA:AA:02:24',
                       subnet='192.168.0.0/24', inNamespace=False)
    net.addLink(nat, s0, bw=50)
    ###########################     Create RAP        ########################
    nat1=net.addHost('nat1', cls=NAT, ip='192.168.0.22', mac='AA:AA:AA:AA:00:22',
                                  subnet='10.0.0.0/24', inNameSpace=False,
                                  inetIntf='nat1-eth0', localIntf='nat1-eth1',
                                  defaultRoute='via 192.168.0.224')
    net.addLink(nat1,s0, bw=15, delay=w_delay)
    net.addLink(ap3, nat1,bw=15, delay='2ms')
    #########################   Build Topology      ##########################
    net.build()
    #########################   Start Topology      ##########################     
    c0.start()
    c1.start()                                               
    ap1.start( [c0] )
    ap3.start( [c0] )
    s0.start( [c1] )
    ########################   Add RAP Interface    ########################## 
    nat1.setIP('10.0.0.22/8', intf='nat1-eth1')

    print "*** Running CLI"
    CLI( net )

    print "*** Stopping network"
    net.stop()


if __name__ == '__main__':
    setLogLevel( 'info' )
    topology()

