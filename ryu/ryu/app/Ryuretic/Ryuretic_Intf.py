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
#                   https://github.gatech.edu/jcox70/RyureticLabs   #
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
        self.stage = 0

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
        #print "handle ARP"
        fields, ops = self.default_Field_Ops(pkt)
        #fields, ops = self.arp_persist(pkt)
        
        #fields, ops = self.Arp_Spoof_Check(pkt)#Lab 10
        self.install_field_ops(pkt,fields,ops)        
		
    def handle_ip(self,pkt):
        print "handle IP"
        #fields, ops = self.TTL_Check(pkt) #Lab 9
	fields, ops = self.default_Field_Ops(pkt) 
        self.install_field_ops(pkt,fields,ops)

    def handle_icmp(self,pkt):
        print "Handle ICMP"
        #fields, ops = self.TTL_Check(pkt)
        fields, ops = self.default_Field_Ops(pkt)
        self.install_field_ops(pkt, fields, ops)

    def handle_tcp(self,pkt):
        #print "handle TCP"
##        fields, ops = self.TTL_Check(pkt)
##        if ops['op'] == 'fwd':
##            fields, ops = self.Multi_MAC_Checker(pkt)
        #fields, ops = self.default_Field_Ops(pkt)
        #fields, ops = self.displayTCPFields(pkt)
        fields, ops = self.displayTCP(pkt)
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

    def displayTCP(self,pkt):
        fields, ops = self.default_Field_Ops(pkt)
        bits = pkt['bits']
        dst = pkt['dstmac']
        dstip = pkt['dstip']
        dstport = pkt['dstport']
        src = pkt['srcmac']
        srcip = pkt['srcip']
        srcport = pkt['srcport']        
        inport = pkt['inport']
        send = (src,srcip,srcport,dstip)
        arrive = (dst,dstip,dstport,srcip)
        t_in = pkt['t_in']

        print "******"
        print self.tta
        print "******"
        print self.port_AV
        print "*******"
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
                                   5) + tta)/6
                        self.port_AV[self.tta[send]['inport']] = portAV
                    else:
                        self.port_AV.update({self.tta[send]['inport']:0.001})
                    print 'Port Averages: ', self.port_AV
                    del self.tta[send]
                    return fields, ops
            print "Persist"
            fields, ops = self.tcp_persist(pkt,fields,ops)
            return fields, ops

        if bits == 24:
            if self.tta.has_key(send):
                del self.tta[send]
            elif self.tta.has_key(arrive):
                del self.tta[arrive]
            print 'Port Averages: ', self.port_AV
            print "HTTP Push"
            
            fields, ops = self.tcp_persist(pkt,fields,ops)
            return fields, ops

        if bits == 17:
            print 'Port Averages: ', self.port_AV
            if self.tta.has_key(send):
                del self.tta[send]
            elif self.tta.has_key(arrive):
                del self.tta[arrive]
            #fields, ops = self.fwd_persist(pkt,fields,ops)
            return fields, ops

        print "Packet not addressed", bits, inport, src, dstip
          
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


    def add_drop_params(self, pkt, fields, ops):
        #may need to include priority
        fields['keys'] = ['inport']
        fields['inport'] = pkt['inport']
        ops['priority'] = 100
        ops['idle_t'] = 60
        ops['op']='drop'
        return fields, ops

    def tcp_persist(self, pkt,fields,ops):
        fields['keys'] = ['inport', 'srcmac', 'srcip', 'ethtype', 'srcport']
        fields['srcport'] = pkt['srcport']
        fields['srcip'] = pkt['srcip']
        ops['idle_t'] = 3
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


##    def displayTCPFields(self,pkt):
##        fields, ops = self.default_Field_Ops(pkt)
##        a = pkt['bits']    
##        #if a != 16 and a != 17 and a != 24:    
##        if a not in [16,17,24]:    
##            print "*******************\n", a, '\n ', a,"\n*******************"    
##        print 'sIP', pkt['srcip'],'\tSEQ:', pkt['seq'], '\tACK:', pkt['ack'], \
##          '\tSport:', pkt['srcport'], '\tDport:', pkt['dstport'], \
##          '\tt_in:', pkt['t_in'], '\tFlags:', pkt['bits']    
##
##        if pkt['srcport'] == 80:    
##            distTuple = (pkt['srcip'],pkt['srcport'])    
##            locTuple = (pkt['dstip'],pkt['dstport'])    
##        else:    
##            locTuple = (pkt['srcip'],pkt['srcport'])    
##            disTuple = (pkt['dstip'],pkt['dstport'])    
##
##        keyFound = self.tta.has_key(locTuple)    
##
##        if keyFound and pkt['srcport'] not in [80,443]:        
##            if self.tta[locTuple]['check'] == False:    
##                ack = self.tta[locTuple]['ack']    
##                t_old = self.tta[locTuple]['t_in']    
##                if pkt['seq'] == ack:    
##                    print '******************\n',pkt['t_in'], ' - ', t_old    
##                    time2ack= pkt['t_in'] - t_old    
##                    self.tta[locTuple]['check'] = True    
##                    if self.ttaAv == 0:    
##                        self.ttaAv = time2ack    
##                    else:    
##                        self.ttaAv = (self.ttaAv + time2ack)/2    
##                    print 'TTA: ', time2ack, '\tTTA Av: ', \
##                          self.ttaAv, '\n************'    
##        elif pkt['srcport'] in [80,443]:    
##            if keyFound != True:    
##                self.tta[locTuple] = {'ack':pkt['ack'], 't_in':pkt['t_in'],\
##                              'check':False, 'cnt':1}   
##            elif keyFound == True:    
##                count = self.tta[locTuple]['cnt']    
##                #print '*********Count: ', count    
##                if self.tta[locTuple]['check'] == True:    
##                    self.tta[locTuple] = {'ack':pkt['ack'], 't_in':pkt['t_in'],\
##                                      'check':False, 'cnt':1}    
##                elif self.tta[locTuple]['check'] == False and count >= 1:    
##                    self.tta[locTuple]['cnt'] = count + 1    
##                    self.tta[locTuple]['t_in'] = pkt['t_in']    
##            else:    
##                print pkt['tcp']
##        return fields, ops
