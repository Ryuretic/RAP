#####################################################################
# Ryuretic: A Modular Framework for RYU                             #
# !/ryu/ryu/app/Ryuretic/Ryuretic_Intf.py                           #
# Authors:                                                          #
#   Jacob Cox (jcox70@gatech.edu)                                   #
#   Sean Donovan (sdonovan@gatech.edu)                              #
# Ryuretic_Intf.py                                                  #
# date 28 April 2016                                                #
#####################################################################
# Copyright (C) 2016 Jacob Cox - All Rights Reserved                #
# You may use, distribute and modify this code under the            #
# terms of the Ryuretic license, provided this work is cited        #
# in the work for which it is used.                                 #
# For latest updates, please visit:                                 #
#                   https://github.com/Ryuretic/RAP                 #
#####################################################################
"""How To Run This Program
1) Ensure you have Ryu installed.
2) Save the following files to /home/ubuntu/ryu/ryu/app/Ryuretic directory
    a) Ryuretic_Intf.py
    b) Ryuretic.py
    c) Pkt_Parse13.py
    d) switch_mod13.py
3) In your controller terminal type: cd ryu
4) Enter PYTHONPATH=. ./bin/ryu-manager ryu/app/Ryuretic/Ryuretic_Intf.py
"""
#########################################################################
from Ryuretic import coupler
#################1     Import Needed Libraries    1######################
#[1] Import needed libraries here                                       #    
#########################################################################
import string, random

class Ryuretic_coupler(coupler):
    def __init__(self, *args, **kwargs):
        super(Ryuretic_coupler, self).__init__(*args, **kwargs)

        ############## 2     Add User Variables     2 ###################
        #[2] Add new global variables here.                             #
        #    Ex. ICMP_ECHO_REQUEST = 8, self.netView = {}               #
        #################################################################
        self.validNAT = 'aa:aa:aa:aa:aa:aa'
        self.port_mac_map = {}
        self.port_AV = {}
        self.tta = {}
        self.ttaAV = {}
        self.check = False
        self.count = 0
        self.tcpConnCount = 0
        self.stage = 0
        self.cntrl ={'mac': 'ca:ca:ca:ad:ad:ad','ip':'192.168.0.40',
                     'port':None}
        self.policyTbl = {}
        self.keyID = 101
        self.t_agent = {}
        ICMP_ECHO_REPLY = 0
        ICMP_ECHO_REQUEST = 8       

    ################ 3       Proactive Rule Sets    3 ###################
    #[3] Insert proactive rules defined below. Follow format below      #
    #    Options include drop or redirect, fwd is the default.          #
    #####################################################################
    def get_proactive_rules(self, dp, parser, ofproto):
        return None, None
        #fields, ops = self.honeypot(dp, parser, ofproto)
        #return fields, ops

    ################# 4     Reactive Rule Sets    4 #####################
    #[4] use below handles to direct packets to reactive user modules   #
    #    defined in location #[5]. If no rule is added, then            #
    #    the default self.default_Fields_Ops(pkt) must be used          #
    #####################################################################
    # Determine highest priority fields and ops pair, if needed         #
    # xfields = [fields0, fields1, fields2]                             #
    # xops = [ops0, ops1, ops2]                                         #
    # fields,ops = self._build_FldOps(xfields,xops)                     #
    #####################################################################    
    def handle_eth(self,pkt):
        #print "handle eth"
        fields, ops = self.default_Field_Ops(pkt)
        self.install_field_ops(pkt,fields,ops)

    def handle_arp(self,pkt):
        print "handle ARP"
        #fields, ops = self.default_Field_Ops(pkt)
        #fields, ops = self.respond_to_arp(pkt)
        fields, ops = self.Arp_Poison(pkt) if pkt['srcip']=='192.168.0.22' \
                      else self.respond_to_arp(pkt)
        #fields, ops = self.arp_persist(pkt)
        
        self.install_field_ops(pkt,fields,ops)        
		
    def handle_ip(self,pkt):
        print "handle IP"
        #fields, ops = self.TTL_Check(pkt) #Lab 9
	fields, ops = self.default_Field_Ops(pkt) 
        self.install_field_ops(pkt,fields,ops)

    def handle_icmp(self,pkt):
        print "Handle ICMP"
        #fields, ops = self.TTL_Check(pkt)
        #fields, ops = self.default_Field_Ops(pkt)
        #fields, ops = self.respond_to_ping(pkt)
        fields, ops = self.Icmp_Redirect(pkt) if pkt['srcip']=='192.168.0.22' \
                      else self.respond_to_ping(pkt)
        self.install_field_ops(pkt, fields, ops)

    def handle_tcp(self,pkt):
        #print "handle TCP"
##        fields, ops = self.TTL_Check(pkt)
##        if ops['op'] == 'fwd':
##            fields, ops = self.Multi_MAC_Checker(pkt)
        #fields, ops = self.default_Field_Ops(pkt)
        #fields, ops = self.displayTCPFields(pkt)
        #fields, ops = self.displayTCP(pkt)
        fields, ops = self.Tcp_Redirect(pkt) if pkt['srcip']=='192.168.0.22'\
                      else self.displayTCP(pkt)
        self.install_field_ops(pkt, fields, ops)       

    def handle_udp(self,pkt):
        #fields, ops = self.TTL_Check(pkt)
        fields, ops = self.default_Field_Ops(pkt)
        self.install_field_ops(pkt, fields, ops)

    # All packets not defined above are handled here.    
    def handle_unk(self,pkt):
        fields, ops = self.default_Field_Ops(pkt)
        self.install_field_ops(pkt, fields, ops)

    #####################################################################
    # The following are from the old NFG file.
    def default_Field_Ops(self,pkt):
        def _loadFields(pkt):
            #keys specifies match fields for action. Default is
            #inport and srcmac. ptype used for craft icmp, udp, etc.
            fields = {'keys':['inport','srcmac'],'ptype':[], 'dp':pkt['dp'],
                      'ofproto':pkt['ofproto'], 'msg':pkt['msg'],
                      'inport':pkt['inport'], 'srcmac':pkt['srcmac'],
                      'ethtype':pkt['ethtype'], 'dstmac':None, 'srcip':None,
                      'proto':None, 'dstip':None, 'srcport':None, 'dstport':None,
                      'com':None, 'id':0}
            return fields
    
        def _loadOps():
            #print "Loading ops"
            #Specifies the timeouts, priority, operation and outport
            #options for op: 'fwd','drop', 'mir', 'redir', 'craft'
            ops = {'hard_t':None, 'idle_t':None, 'priority':10, \
                   'op':'fwd', 'newport':None}
            return ops
        
        #print "default Field_Ops called"
        fields = _loadFields(pkt)
        ops = _loadOps()
        return fields, ops
    #####################################################################

    ############ 5  Ryuretic Network Application Modules  5 ##############   
    #[5] Add user created methods below. Examples are provided to assist #
    # the user with basic python, dictionary, list, and function calls   #
    ######################################################################
    # Confirm mac has been seen before and no issues are recorded
    def TTL_Check(self, pkt):
        #initialize fields and ops with default settings
        fields, ops = self.default_Field_Ops(pkt)
        if pkt['srcmac'] != self.validNAT:
            if pkt['ttl']==63 or pkt['ttl']==127:
                print 'TTL Decrement Detected on ', pkt['srcmac'], ' TTL is :', pkt['ttl']
                fields, ops = self.add_drop_params(pkt,fields,ops)
            else:
                ops['idle_t'] = 5
            print "Packet TTL: ", pkt['ttl'], '  ', pkt['srcip'],' ', \
                  pkt['inport'],' ', pkt['srcmac']
        else:
            ops['idle_t'] = 20
            priority = 10
        return fields, ops

    def Multi_MAC_Checker(self, pkt):
        fields, ops = self.default_Field_Ops(pkt)
        print "*** Checking MAC ***"
        #self.port_mac_map = {}
        if self.port_mac_map.has_key(pkt['inport']):
            if pkt['srcmac'] != self.port_mac_map[pkt['inport']]:
                print " Multi-mac port detected "
                fields, ops = self.add_drop_params(pkt,fields,ops)
            else:
                fields, ops = self.fwd_persist(pkt,fields,ops)
        else:
            self.port_mac_map[pkt['inport']] = pkt['srcmac']
        return fields, ops

    #change name to monitor_TCP for RAP
    def displayTCP(self,pkt):
        fields, ops = self.default_Field_Ops(pkt)
        bits = pkt['bits']
        dst, dstip, dstport = pkt['dstmac'], pkt['dstip'], pkt['dstport']
        src, srcip, srcport = pkt['srcmac'], pkt['srcip'], pkt['srcport']     
        inport = pkt['inport']
        send = (src,srcip,srcport,dstip)
        arrive = (dst,dstip,dstport,srcip)
        t_in = pkt['t_in']

        #print "******\n"+self.tta+"/n********/n"+self.port_AV+"/n*********"

        if bits == 20:
            if self.tta.has_key(send):
                self.tta[send]['stage'] = 0
            else:
                self.tta[arrive]['stage'] = 0
            return fields, ops
            
        if bits == 2:
            if self.tta.has_key(send):
                self.tta[send].update({'inport':inport,'stage':1})
            else:
                self.tta.update({send:{'inport':inport,'stage':1}})
            return fields, ops

        if bits == 18:
            if self.tta.has_key(arrive):
                if self.tta[arrive]['stage']==1:
                    self.tta[arrive].update({'syn':t_in,'stage':2})
            return fields,ops

        if bits == 16:
            if self.tta.has_key(send):
                if self.tta[send]['stage']==2:
                    tta = t_in - self.tta[send]['syn']
                    self.tta[send].update({'stage':3, 'ack':t_in, 'tta':tta})
                    print '** Calc TTA :', tta
                    if self.port_AV.has_key(self.tta[send]['inport']):
                        portAV = ((self.port_AV[self.tta[send]['inport']] * \
                                   9) + tta)/10
                        self.port_AV[self.tta[send]['inport']] = portAV
                    else:
                        portAV = ((0.001*9)+tta)/10
                        self.port_AV.update({self.tta[send]['inport']:portAV})
                    print "****"
                    print "Port and TTA: ", inport, self.tta[send]['tta']
                    print '\nPort Averages: ', self.port_AV
                    print "****"
                    del self.tta[send]
                    return fields, ops
            print "Persist"
            fields, ops = self.tcp_persist(pkt,fields,ops)
            return fields, ops

        if bits == 24:
            print "HTTP Push"
            return fields, ops

        if bits == 17:
            print 'Port Averages: ', self.port_AV
            if self.tta.has_key(send):
                del self.tta[send]
            elif self.tta.has_key(arrive):
                del self.tta[arrive]
            return fields, ops

        print "Packet not addressed", bits, inport, src, dstip
          
        return fields, ops


    # Call to temporarily install drop parameter for a packet to switch
    def add_drop_params(self, pkt, fields, ops):
        #may need to include priority
        fields['keys'] = ['inport']
        fields['inport'] = pkt['inport']
        ops['priority'] = 100
        ops['idle_t'] = 60
        ops['op']='drop'
        return fields, ops
    # Call to temporarily install TCP flow connection on switch
    def tcp_persist(self, pkt,fields,ops):
        fields['keys'] = ['inport', 'srcmac', 'srcip', 'ethtype', 'srcport']
        fields['srcport'] = pkt['srcport']
        fields['srcip'] = pkt['srcip']
        ops['idle_t'] = 5
        ops['priority'] = 10
        return fields, ops
    
    def fwd_persist(self, pkt,fields,ops):
        ops['idle_t'] = 3
        ops['priority'] = 10
        return fields, ops

    def arp_persist(self, pkt):
        fields, ops = self.default_Field_Ops(pkt)
        fields['keys'] = ['inport','srcmac','ethtype']
        ops['idle_t'] = 10
        ops['priority'] = 2
        return fields, ops
    #####################################################################
    """
    The following code is implemented to allow our trusted agent to comm
    with the controller and vice versa. 
    """
    #####################################################################

    #Receive and respond to arp
    def respond_to_arp(self,pkt):
        #print 'Respond to Arp Called'
        fields, ops = self.default_Field_Ops(pkt)
        if pkt['dstip'] == self.cntrl['ip']:
            print "Message to Controller"
            fields['keys']=['srcmac', 'srcip', 'ethtype', 'inport']
            fields['ptype'] = 'arp'
            fields['dstip'] = pkt['srcip']
            fields['srcip'] = self.cntrl['ip']
            fields['dstmac'] = pkt['srcmac']
            fields['srcmac'] = self.cntrl['mac']
            fields['ethtype'] = 0x0806
            ops['op'] = 'craft'
            ops['newport'] = pkt['inport']
            #print "INPORT: ", pkt['inport']
        return fields, ops
    
    #Respond to ping. Forward or respond if to cntrl from trusted agent. 
    def respond_to_ping(self,pkt):
        fields, ops = self.default_Field_Ops(pkt)
        print "\n\nRespond to Ping"
        print pkt['dstip'], self.cntrl['ip'], pkt['srcip']
        if pkt['dstip'] == self.cntrl['ip'] and pkt['srcip'] == '192.168.0.1':
            #print'respond to ping'
            rcvData = pkt['data'].data
            #Possible actions {i-init, d-delete, v-verify, 
            action, keyID = rcvData.split(',')
            
            keyID = keyID.rstrip(' \t\r\n\0')
            print len(keyID)
            keyID = int(keyID)
            print "Action is ", action
            print "KeyID is ", keyID, ', ', type(keyID)
            
            print "\n\n\n*********"
            ########################################
            if action == 'i':
                  self.t_agent = {'ip':pkt['srcip'],'mac':pkt['srcmac'],
                                  'port':pkt['inport'],'msg':pkt['msg'],
                                  'ofproto':pkt['ofproto'], 'dp':pkt['dp']}
            elif action == 'd':
                #Deleting flagged host policy
                print "Deleting Policy Table"
                print self.policyTbl.has_key(keyID)
                print self.policyTbl.keys()
                if self.policyTbl.has_key(keyID):
                    srcmac = self.policyTbl[keyID]['srcmac']
                    inport = self.policyTbl[keyID]['inport']
                    print srcmac, ', ', inport
                    if self.net_MacTbl.has_key(srcmac):
                        print "Found MAC"
                        self.net_MacTbl.pop(srcmac)
                    if self.net_PortTbl.has_key(inport):
                        print "Found Port"
                        self.net_PortTbl.pop(inport)
                    self.policyTbl.pop(keyID)
            elif action is 'u':
                #This is more complicated it requires data not being stored
                #may need to add fields to policyTable. Maybe not. 
                pass
            elif action is 'a':
                #Acknowledge receipt
                pass
            else:
                print "No match"
                
            fields['dstip'] = pkt['srcip']
            fields['srcip'] = self.cntrl['ip']
            fields['dstmac'] = pkt['srcmac']
            fields['srcmac'] = self.cntrl['mac']
            
            fields['ptype'] = 'icmp'
            fields['ethtype'] = 0x0800
            fields['proto'] = 1
            fields['com'] = 'a,'+rcvData
            ops['op'] = 'craft'
            ops['newport'] = pkt['inport']

        return fields, ops
       
    #Builds notification information for trusted agent and sends if via
    # self.update_TA (may want to combine these two definitions
    def notify_TA(self, pkt,status):
        keyID = self.keyID
        self.keyID += 1
        print "Adding Violation, passkey, and updating keyID"
        violation = status # 's' or 't'
        #create passkey
        passkey =''.join(random.choice(string.ascii_letters) for x in range(8))
        #update policy table
        self.policyTbl[keyID]={'inport':pkt['inport'], 'srcmac':pkt['srcmac'],
                               'passkey':passkey, 'violation':violation}
        #Notify trusted agent of newly flagged client
        self.update_TA(pkt, keyID, status)

        return keyID
    
    #Crafts tailored ICMP message for trusted agent
    def update_TA(self,pkt, keyID, status):
        table = self.policyTbl[keyID]
        #print "Updating Trusted Agent"
        fields, ops = {},{}
        fields['keys'] = ['inport', 'srcip']
        fields['dstip'] = self.t_agent['ip']
        fields['srcip'] = self.cntrl['ip']
        fields['dstmac'] = self.t_agent['mac']
        fields['srcmac'] = self.cntrl['mac']
        fields['dp'] = self.t_agent['dp']
        fields['msg'] = self.t_agent['msg']
        fields['inport'] = self.t_agent['port']
        fields['ofproto']=self.t_agent['ofproto']
        fields['ptype'] = 'icmp'
        fields['ethtype'] = 0x0800
        fields['proto'] = 1
        fields['id'] = 0
        fields['com'] = table['srcmac']+','+str(table['inport'])+\
                        ','+str(table['passkey'])+','+table['violation']+\
                        ','+str(keyID)
        
        ops = {'hard_t':None, 'idle_t':None, 'priority':0, \
                   'op':'fwd', 'newport':None}
        ops['op'] = 'craft'
        ops['newport'] = self.t_agent['port']
        
        self.install_field_ops(pkt, fields, ops)

    #Respond to ping. Forward or respond if to cntrl from trusted agent. 
    def respond_to_ping(self,pkt):
        fields, ops = self.default_Field_Ops(pkt)
        #print "\n\nRespond to Ping"
        print pkt['dstip'], self.cntrl['ip'], pkt['srcip']
        if pkt['dstip'] == self.cntrl['ip'] and pkt['srcip'] == '192.168.0.1':
            #print'respond to ping'
            rcvData = pkt['data'].data
            #Possible actions {i-init, d-delete, v-verify, 
            action, keyID = rcvData.split(',')
            
            keyID = keyID.rstrip(' \t\r\n\0')
            print len(keyID)
            keyID = int(keyID)
            print "Action is ", action
            print "KeyID is ", keyID, ', ', type(keyID)
            
            print "\n\n\n*********"
            ########################################
            if action == 'i':
                  self.t_agent = {'ip':pkt['srcip'],'mac':pkt['srcmac'],
                                  'port':pkt['inport'],'msg':pkt['msg'],
                                  'ofproto':pkt['ofproto'], 'dp':pkt['dp']}
            elif action == 'd':
                #Deleting flagged host policy
                print "Deleting Policy Table"
                print self.policyTbl.has_key(keyID)
                print self.policyTbl.keys()
                if self.policyTbl.has_key(keyID):
                    srcmac = self.policyTbl[keyID]['srcmac']
                    inport = self.policyTbl[keyID]['inport']
                    print srcmac, ', ', inport
                    if self.net_MacTbl.has_key(srcmac):
                        print "Found MAC"
                        self.net_MacTbl.pop(srcmac)
                    if self.net_PortTbl.has_key(inport):
                        print "Found Port"
                        self.net_PortTbl.pop(inport)
                    self.policyTbl.pop(keyID)
            elif action is 'u':
                #This is more complicated it requires data not being stored
                #may need to add fields to policyTable. Maybe not. 
                pass
            elif action is 'a':
                #Acknowledge receipt
                pass
            else:
                print "No match"
                   
            fields['dstip'] = pkt['srcip']
            fields['srcip'] = self.cntrl['ip']
            fields['dstmac'] = pkt['srcmac']
            fields['srcmac'] = self.cntrl['mac']
            
            fields['ptype'] = 'icmp'
            fields['ethtype'] = 0x0800
            fields['proto'] = 1
            fields['com'] = 'a,'+rcvData
            ops['op'] = 'craft'
            ops['newport'] = pkt['inport']

        return fields, ops
    #########################################################################
    """
    The following code controls the redirection of packets from their intended
    destination to our trusted agent. This occurs when a port is flagged. 
    """
    #########################################################################
    #Create a method to inject a redirect anytime the sta4 IP address is
    
    #Check status of port and mac. 
    def check_net_tbl(self,mac,port=0):
        if mac in self.macTbl.keys():
            print mac, " found in table."         
            return self.macTbl[mac]['stat']
        elif port in self.portTbl.keys():
            print "Port ", port, " found in table."
            return self.portTbl[port]['stat']
        else:
            return None
    

    def addToNetView(self,pkt,status='noStat',passkey='noPass'):
        keyID = self.keyID
        self.netView[keyID]={'srcmac':pkt['srcmac'], 'inport':pkt['inport'],
                             'srcip':pkt['srcip'], 'stat':status, 'passkey':passkey}
        self.macTbl[pkt['srcmac']]= keyID
        if self.portTble.has_key(pkt['inport']):
            print "Port already assigned"
        else:
            self.portTbl[pkt['inport']]= keyID
        self.keyID += keyID

    def flagInNetView(self,pkt,status):
        if self.macTbl.has_key(pkt['srcmac']):
            keyID = self.MacTbl[pkt['srcmac']]
            if self.netView.has_key(keyID):
                tbl = self.netView[keyID]
                tbl['stat']=status
                tbl['passkey']= ''.join(random.choice(string.ascii_letters) for x in range(8))
                self.notify_TA(pkt,status)
        else:
            print "This MAC has yet to be added to the netView Table"
                        
                       
    def arp_tester(self,pkt):
        #Determin if mac or port has a status
        pkt_status = self.check_net_tbl(pkt['srcmac'],pkt['inport'])
        if pkt_status =='test':
            fields,ops = self.Arp_Poison(pkt)
        elif pkt_status == 'drop':
            field,ops == self.drop_ARP(pkt)
        elif pkt_status == None:
            self.addToNetVeiw(pkt)
            fields, ops = self.respond_to_arp(pkt)
        else:
            fields, ops = self.respond_to_arp(pkt) 
        return fields, ops           
  
    def Arp_Poison(self,pkt):
        print "Building Arp poison"
        fields, ops = self.default_Field_Ops(pkt)
        if pkt['opcode'] != 2: 
            fields['keys']=['srcmac', 'srcip', 'ethtype', 'inport']
            fields['ptype'] = 'arp'
            fields['ethtype'] = 0x0806 #pkt['ethtype']
            print "Ethernet Type is : ", pkt['ethtype'], type(pkt['ethtype'])
            fields['srcmac'] = self.t_agent['mac']
            fields['dstmac'] = pkt['srcmac']
            fields['srcip'] = pkt['dstip'] #self.t_agent['ip']
            fields['dstip'] = pkt['srcip']
            ops = {'hard_t':None, 'idle_t':None, 'priority':100, \
                       'op':'craft', 'newport':pkt['inport']}
        return fields,ops

    def drop_ARP(self, pkt):
        if pkt['dstip'] != self.t_agent['ip']:
            fields, ops = self.default_Field_Ops(pkt)
            fields['keys'] = ['inport', 'ethtype', 'proto']
            fields['inport'] = pkt['inport']
            fields['ethtype'] = pkt['ethtype']
            fields['proto'] = pkt['proto']
            ops['priority'] = 100
            ops['op']='drop'
            ops['idle_t'] = 120
            print "(319) Droping ARP. Fields are: ", fields
        return fields, ops


    #Use this to flag during a TCP connection.
    def flag_Sta4(self,pkt):
        policyFlag = False
        if pkt['srcip']=='192.168.0.22':
            #change mac or port status in netView
            self.flagInNetView(pkt,'test')
            policyFlag = True
        return policyFlag

    def tcp_tester(self,pkt):
        pkt_status = self.check_net_tbl(pkt['srcmac'], pkt['inport'])
        if pkt_status =='test':
            fields,ops = self.Tcp_Redirect(pkt)
        elif pkt_status == 'noStat':
            fields, ops = self.default_Field_Ops(pkt)
            flag = self.flag_Sta4(pkt)
            if flag:
                self.flagInNetView(pkt,'test')
                #field,ops = self.drop_TCP(pkt)
                fields['keys'] = ['inport']
                fields['inport'] = pkt['inport']
                ops['priority'] = 100
                #ops['idle_t'] = 5
                ops['op']='drop'
        else:
            fields, ops = self.default_Field_Ops(pkt)
        return fields, ops 

    #Redirect ICMP packets to trusted agent
    def Icmp_Redirect(self,pkt):
        print "Redirecting ICMP"
        fields, ops = self.default_Field_Ops(pkt)
        fields['keys'] = ['inport', 'ethtype']
        fields['dstmac'] = self.t_agent['mac']
        fields['dstip'] = self.t_agent['ip']
        fields['ethtype'] = pkt['ethtype']
        ops['op'] = 'redir'
        ops['newport'] = self.t_agent['port']
        ops['priority'] = 100
        ops['idle_t'] = 180
        #ops['hard_t'] = 180
        return fields, ops

    def Tcp_Redirect(self,pkt):
        print "*\n*\nRedirecting TCP"
        print pkt
        fields, ops = self.default_Field_Ops(pkt)
        fields['keys'] = ['inport', 'ethtype']
        fields['dstmac'] = self.t_agent['mac']
        fields['dstip'] = pkt['dstip'] #self.t_agent['ip']
        fields['ethtype'] = pkt['ethtype']
        ops['op'] = 'redir'
        ops['newport'] = self.t_agent['port']
        ops['priority'] = 100
        ops['idle_t'] = 180
        #ops['hard_t'] = 180
        return fields, ops

    

#############################################################################
#############################################################################
    def Simple_FW(self,pkt):
        fields, ops = self.default_Field_Ops(pkt)
        #blocking w3cschools and facebook
        if pkt['dstip'] in ['141.8.225.80', '173.252.120.68']:
            print "W3Cschools or Facebook is not allowed"
            #tell controller to drop pkts destined for dstip
            fields['keys'],fields['dstip'] = ['dstip'],pkt['dstip']
            ops['priority'] = 100
            ops['op']= 'drop'
            ops['idle_t']=60
        return fields, ops
        

    def Stateful_FW(self,pkt):
        fields, ops = self.default_Field_Ops(pkt)
        if pkt['input'] in [1,2,3,4,5,6,7,8]:
            if self.stat_Fw_tbl.has_key(pkt['srcip']):
                if len(self.stat_Fw_tbl[pkt['srcip']]['dstip']) > 4:
                    self.stat_Fw_tbl[pkt['srcip']]['dstip'].pop(3)
                self.self.stat_Fw_tbl[pkt['srcip']]['dstip'].append(pkt['dstip'])
            else:
                self.stat_Fw_tbl[pkt['srcip']]={'dstip':[pkt['dstip']]}
            return fields, ops
        else:
            if self.stat_Fw_tbl.has_key(pkt['dstip']):
                if pkt['srcip'] in stat_Fw_tbl[pkt['dstip']]['dstip']:
                    return fields, ops
                else:
                    fields['keys'] = ['srcip','dstip']
                    fields['srcip'] = pkt['srcip']
                    fields['dstip'] = pkt['dstip']
                    ops['priority'] = 100
                    ops['op']='drop'
                    #ops['hard_t'] = 20
                    ops['idle_t'] = 4
                    return fields, ops

    def honeypot(self, dp, parser, ofproto):
        # This should install proactive rules that mirrors data from a 
        # honeypot system
        fields, ops = {}, {}
        fields['ethtype'] = 0x0800
        fields['keys'] = ['srcip']
        fields['srcip'] = '10.0.0.42'
        ops['priority'] = 100
        ops['op'] = 'mir'
        ops['newport'] = 2
        #could make this multicast as well [1,2,3]

        return fields, ops


    def displayTCP2(self,pkt):
        fields, ops = self.default_Field_Ops(pkt)
        bits = pkt['bits']
        dst = pkt['dstmac']
        src = pkt['srcmac']
        inport = pkt['inport']
        print '*******', inport, src, bits, self.stage #, self.check

        if bits in [2,16,18]:
            print '**SEQ: ', pkt['seq'], '\tACK ', pkt['ack'], ' **'
            if bits == 2:
                self.tta[src]= {}
                self.tta[src]['inport'] = pkt['inport']
                #self.check=True
                self.stage=1
            #Somehow this is not always sent(need to resolve error that ocurs here
            #So far, AP stands out, but not the NAT (comparable to NAT)
            elif bits == 18 and self.stage==1:
                self.tta[dst]['syn'] = pkt['t_in']
                self.stage = 2
            elif bits == 16  and self.stage == 2: #self.check==True:
                self.stage=3
                self.tta[src]['ack'] = pkt['t_in']
                tta = pkt['t_in'] - self.tta[src]['syn']
                if self.ttaAV.has_key(inport):
                    self.ttaAV[inport]= (self.ttaAV[inport] + tta)/2
                else:
                    self.ttaAV[inport]= tta
                print self.ttaAV[inport]
                print '\n**** Port: ',inport,'   TTA = ', tta, ' ********\n'
                self.count = self.count + 1
                fields, ops = self.fwd_persist(pkt,fields,ops)
                
                #self.check = False
            else:
                self.stage=0
                fields, ops = self.fwd_persist(pkt,fields,ops)
        else:
            fields, ops = self.fwd_persist(pkt,fields,ops)
        print self.ttaAV
            
        return fields, ops
