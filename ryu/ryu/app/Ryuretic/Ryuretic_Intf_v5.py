#########################################################################
# Ryuretic: A Modular Framework for RYU								 	#
# !/ryu/ryu/app/Ryuretic/Ryuretic_Intf.py                       	 	#
# Authors:                                                         	 	#
#   Jacob Cox (jcox70@gatech.edu)                                		#
#   Sean Donovan (sdonovan@gatech.edu)                          	 	#
# Ryuretic_Intf.py                                                   	#
# date 28 April 2016                                               	 	#
#########################################################################
# Copyright (C) 2016 Jacob Cox - All Rights Reserved                 	#
# You may use, distribute and modify this code under the             	#
# terms of the Ryuretic license, provided this work is cited         	#
# in the work for which it is used.                                  	#
# For latest updates, please visit:                                  	#
#                   https://github.com/Ryuretic/RAP                  	#
#########################################################################
"""How To Run This Program
	1) Ensure you have Ryu installed.
	2) Save the following files to /home/ubuntu/ryu/ryu/app/Ryuretic directory
		a) Ryuretic_Intf.py
		b) Ryuretic.py
		c) Pkt_Parse13.py
		d) switch_mod13.py
	3) In your controller terminal type: cd ryu
	4) Enter PYTHONPATH=. ./bin/ryu-manager ryu/app/Ryuretic/Ryuretic_Intf_v1.py
"""
#########################################################################
from Ryuretic import coupler
#################1     Import Needed Libraries    	 1###################
#[1] Import needed libraries here                                    	#    
#########################################################################
import string, random

class Ryuretic_coupler(coupler):
	def __init__(self, *args, **kwargs):
		super(Ryuretic_coupler, self).__init__(*args, **kwargs)

		############## 2     Add User Variables     2 ###################
		#[2] Add new global variables here.                             #
		#    Ex. ICMP_ECHO_REQUEST = 8, self.netView = {}               #
		#################################################################
		self.cntrl = {'mac':'ca:ca:ca:ad:ad:ad','ip':'192.168.0.40','port':None}
		self.validNAT = {'mac':'aa:aa:aa:aa:aa:aa','ip':'192.168.0.224'}
		self.t_agentIP = '192.168.0.1'
		self.t_agent = {} #Records TA parameter from respond_to_ping
		self.dns_tbl = {} #Use to redirect DNS
		self.tcp_tbl = {} #Use to redirect TCP
		self.port_mac_map = {} #Used by multi-mac detector
		self.port_AV = {} #Tracks per port Time-2-ack average
		self.tta = {}     #Tracks TCP handshake per (src,srcip,srcport,dstip)
		self.tcpConnCount = 0 #Future var for tracking total TCP connections
		self.policyTbl = {} #Tracks policies applied to port/mac
		self.netView = {} #Maps switch connections by port,mac,ip
		self.portTbl, self.macTbl, self.ipTbl = {},{},{}
		self.testIP = '192.168.0.22'
		#self.portTbl[9]='test'
		#self.macTbl['aa:aa:aa:aa:00:22'] = 'test'
		#self.ipTbl['192.168.0.22'] = 'test'
		#Assigns flag to MAC/Port
		self.keyID = 101
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
		print "Handle Ether: ", pkt['srcmac'],'->',pkt['dstmac']
		fields, ops = self.default_Field_Ops(pkt)
		self.install_field_ops(pkt,fields,ops)

	#def handle_arp(self,pkt):
		#print "-------------------------------------------------------------"
		#print "Handle ARP: ",pkt['srcmac'],"->",pkt['dstmac']
		#print "Handle ARP: ",pkt['srcip'],"->",pkt['dstip']
		#fields, ops = self.respond_to_arp(pkt)
		##Determin if mac or port has a status
		##pkt_status = self.check_net_tbl(pkt['srcmac'],pkt['inport'])
		##print pkt_status   
		#self.install_field_ops(pkt,fields,ops)
		
	def handle_arp(self,pkt):
		print "-------------------------------------------------------------"
		print "Handle ARP: ",pkt['srcmac'],"->",pkt['dstmac']
		print "Handle ARP: ",pkt['srcip'],"->",pkt['dstip']
		fields, ops = self.respond_to_arp(pkt)
		self.install_field_ops(pkt,fields,ops)
		
	def handle_ip(self,pkt):
		print "-------------------------------------------------------------"
 		print "Handle IP"
		#fields, ops = self.TTL_Check(pkt) #Lab 9
		fields, ops = self.default_Field_Ops(pkt) 
		self.install_field_ops(pkt,fields,ops)

	def handle_icmp(self,pkt):
		print "-------------------------------------------------------------"
		print "Handle ICMP: ",pkt['srcmac'],"->",pkt['dstmac']
		print "Handle ICMP: ",pkt['srcip'],"->",pkt['dstip']
		fields,ops = self.respond_to_ping(pkt)
		self.install_field_ops(pkt, fields, ops)

	def handle_tcp(self,pkt):
		print "-------------------------------------------------------------"
		print "Handle TCP: ",pkt['srcmac'],"->",pkt['dstmac']
		print "Handle TCP: ",pkt['srcip'],"->",pkt['dstip']
		print "Handle TCP: ",pkt['srcport'],"->",pkt['dstport']
		pkt_status = self.check_ip_tbl(pkt)
		if pkt_status == 'test': #test src and dest
			fields,ops = self.redirect_TCP(pkt)
		else:
			#fields,ops = self.default_Field_Ops(pkt)
			fields,ops = self.test_TCP(pkt)
		self.install_field_ops(pkt, fields, ops)	
		
	def test_TCP(self,pkt):
		fields,ops = self.default_Field_Ops(pkt)
		if pkt['srcip'] == self.testIP:
			print "IP detected: ", pkt['srcip']
			self.flagHost(pkt,'test')
			fields,ops=self.redirect_TCP(pkt)
			return fields,ops
		return fields,ops
			
		
	def redirect_TCP(self,pkt):
		print "Redirect_TCP: "
		print "pkt info: ", pkt['srcmac'],' ',pkt['dstmac'],' ',pkt['srcip'],' ',pkt['dstip']
		print pkt['srcport'],' ',pkt['dstport']
		#Uses ipTbl, tcp_tbl, and t_agent 	
		fields,ops = self.default_Field_Ops(pkt)
			
		if self.ipTbl.has_key(pkt['srcip']):
			if self.ipTbl[pkt['srcip']]== 'test':
				key = (pkt['srcip'],pkt['srcport'])
				print "Key is : ", key
				self.tcp_tbl[key] = {'dstip':pkt['dstip'],'dstmac':pkt['dstmac'],
						 'dstport':pkt['dstport']}
				fields.update({'srcmac':pkt['srcmac'],'srcip':pkt['srcip']})
				fields.update({'dstmac':self.t_agent['mac'],'dstip':self.t_agent['ip']})
				#if pkt['dstport'] == 443:
					#fields['dstport'] = 80
				ops = {'hard_t':None, 'idle_t':None, 'priority':100,\
					'op':'mod', 'newport':self.t_agent['port']}
				print "TCP Table: ", self.tcp_tbl[key]
				
		elif self.ipTbl.has_key(pkt['dstip']):
			print "Returning to ", pkt['dstip']
			if self.ipTbl[pkt['dstip']]== 'test':
				key = (pkt['dstip'],pkt['dstport'])
				print "Key and table: ", key, ' ', self.tcp_tbl[key]
				
				fields.update({'srcmac':self.tcp_tbl[key]['dstmac'],
				   'srcip':self.tcp_tbl[key]['dstip']})
				#if self.tcp_tbl[key]['dstport'] == 443:
					#fields.update({'srcport':443})
				fields.update({'dstmac':pkt['dstmac'], 'dstip':pkt['dstip']})
				ops = {'hard_t':None, 'idle_t':None, 'priority':100,\
					'op':'mod', 'newport':None}	
				#self.tcp_tbl.pop(key)
				#print "TCP Table: ", self.tcp_tbl
		return fields, ops		
	
	# Add flag to policyTbl, macTbl, portTbl
	def flagHost(self,pkt,flag):
		print 'Flag Host: ', pkt['srcmac'],'->',flag
		self.macTbl[pkt['srcmac']]={'stat':flag,'port':pkt['inport'],
							  'ip':pkt['srcip']}
		self.portTbl[pkt['inport']]=flag
		self.ipTbl[pkt['srcip']] = flag
		if flag != 'norm':	
			keyID = self.keyID
			self.keyID += 1
			#create passkey
			passkey =''.join(random.choice(string.ascii_letters) for x in range(8))
			#update policy table
			self.policyTbl[keyID]={'inport':pkt['inport'],'srcmac':pkt['srcmac'],
								   'ip':pkt['srcip'],'passkey':passkey,'stat':flag}

			#Notify trusted agent of newly flagged client
			self.update_TA(pkt, keyID, 'l')  #load message'
		
	def handle_udp(self,pkt):
		print "-------------------------------------------------------------"
		print "Handle UDP: ",pkt['srcmac'],"->",pkt['dstmac']
		print "Handle UDP: ",pkt['srcip'],'->',pkt['dstip']
		#Added to build MAC and port associations	
		pkt_status = self.check_ip_tbl(pkt)
		if pkt_status == 'test': #test src and dest
			fields,ops = self.redirect_DNS(pkt)
		else:
			fields,ops = self.test_DNS(pkt)
		self.install_field_ops(pkt, fields, ops)
		
	def test_DNS(self,pkt):
		print "Testing DNS"
		fields,ops = self.default_Field_Ops(pkt)
		if pkt['srcip'] == self.testIP:
			print "IP detected: ", pkt['srcip']
			self.flagHost(pkt,'test')
			fields,ops=self.redirect_DNS(pkt)
			return fields,ops
		return fields,ops
	
	def redirect_DNS(self,pkt):
		print "Redirect_DNS: "
		#Uses macTbl, dns_tbl, and t_agent 	
		fields,ops = self.default_Field_Ops(pkt)
		if self.ipTbl.has_key(pkt['srcip']):
			if self.ipTbl[pkt['srcip']]== 'test':
				key = (pkt['srcip'],pkt['srcport'])
				print key
				self.dns_tbl[key] = {'dstip':pkt['dstip'],'dstmac':pkt['dstmac']}
				fields.update({'dstmac':self.t_agent['mac'],
				   'dstip':self.t_agent['ip']})
				fields.update({'srcmac':pkt['srcmac'],'srcip':pkt['srcip']})
				ops = {'hard_t':None, 'idle_t':None, 'priority':100,\
					'op':'mod', 'newport':self.t_agent['port']}
		elif self.ipTbl.has_key(pkt['dstip']):
			if self.ipTbl[pkt['dstip']]== 'test':
				key = (pkt['dstip'],pkt['dstport'])
				print key
				fields.update({'srcmac':self.dns_tbl[key]['dstmac'],
				   'srcip':self.dns_tbl[key]['dstip']})
				fields.update({'dstmac':pkt['dstmac'], 'dstip':pkt['dstip']})
				ops = {'hard_t':None, 'idle_t':None, 'priority':100,\
					'op':'mod', 'newport':None}	
				#self.dns_tbl.pop(key)
				#print "DNS Table: ", self.dns_tbl
		return fields, ops
	
	#Check status of port and mac. 
	def check_ip_tbl(self,pkt):
		print "Check_ip_tbl:"
		srcip,dstip = pkt['srcip'],pkt['dstip']
		if self.ipTbl.has_key(srcip):
			print "Found: ", srcip,'->', self.ipTbl[srcip]		 
			return self.ipTbl[srcip]
		elif self.ipTbl.has_key(dstip):
			print "Found: ", dstip,'->', self.ipTbl[dstip]		 
			return self.ipTbl[dstip]
		else:
			print "Not Found: ", srcip, ', ', dstip
			return 'No_Flag'	
				

	# All packets not defined above are handled here.    
	def handle_unk(self,pkt):
		print "-------------------------------------------------------------"
		print "Handle Uknown"
		fields, ops = self.default_Field_Ops(pkt)
		self.install_field_ops(pkt, fields, ops)

	######################################################################
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
	######################################################################
	############ 5  Ryuretic Network Application Modules  5 ##############   
	#[5] Add user created methods below. Examples are provided to assist #
	# the user with basic python, dictionary, list, and function calls   #
	######################################################################
	# Confirm mac has been seen before and no issues are recorded
	def TTL_Check(self, pkt):
		#initialize fields and ops with default settings
		fields, ops = self.default_Field_Ops(pkt)
		if pkt['srcmac'] != self.validNAT['mac']:
			if pkt['ttl']==63 or pkt['ttl']==127:
				print 'TTL Decrement Detected on ',pkt['srcmac'],' TTL is :',pkt['ttl']
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
		
		#print"*****\n"+self.tta+"/n******/n"+self.port_AV+"/n*****"

		if bits == 20:
			if self.tta.has_key(send):
				self.tta[send]['stage'] = 0
			elif self.tta.has_key(arrive):
				#print pkt
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
		print "TCP_Persist: ", pkt['srcmac'],'->', pkt['dstmac']
		print "TCP_Persist: ", pkt['srcip'],'->',pkt['dstip']
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
	
	################################################################
	"""
	The following code is implemented to allow the trusted agent to comm
	with the controller and vice versa. 
	"""
	################################################################
	#Receive and respond to arp
	def respond_to_arp(self,pkt):
		print 'Respond to Arp:', pkt['srcmac'],'->',pkt['dstmac']
		print 'Respond to Arp:', pkt['srcip'],'->',pkt['dstip']
		fields, ops = self.default_Field_Ops(pkt)
		#Added to build MAC and port associations
		if not self.macTbl.has_key(pkt['srcmac']):
			self.macTbl[pkt['srcmac']] = {'port':pkt['inport'], 'stat':'unk'}
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
		def get_fields(keyID):
			srcmac = self.policyTbl[keyID]['srcmac']
			inport = self.policyTbl[keyID]['inport']
			srcip = self.policyTbl[keyID]['ip']					
			print inport, ', ', srcmac, ', ', srcip
			return srcmac, inport, srcip
		
		def remove_keyID(keyID):
			if self.policyTbl.has_key(keyID):
				srcmac, inport, srcip = get_fields(keyID)
				if self.macTbl.has_key(srcmac):
					print "Removing MAC", srcmac
					self.macTbl.pop(srcmac)
				if self.portTable.has_key(inport):
					print "Removing Port", inport
					self.portTable.pop(inport)
				if self.portTable.has_key(srcip):
					print "Removing IP", IP
					self.portTable.pop(IP)					
				self.policyTbl.pop(keyID)	
				
		print "Respond to Ping: ", pkt['srcmac'],'->',pkt['dstmac']
		fields, ops = self.default_Field_Ops(pkt)
		if pkt['dstip'] == self.cntrl['ip'] and pkt['srcip'] == self.t_agentIP:
			#print'respond to ping'
			rcvData = pkt['data'].data
			#Actions {a-acknowledge, i-init, d-delete, r-result, v-verify} 
			#action, keyID = rcvData.split(',')
			#keyID = keyID.rstrip(' \t\r\n\0')
			print rcvData
			action, keyID, result = rcvData.split(',')
			keyID = keyID.rstrip(' \t\r\n\0')
			result = result.rstrip(' \t\r\n\0')
			print "Key ID Length: ", len(keyID)
			keyID = int(keyID)
			print "KeyID is ", keyID, ', ', type(keyID)
			print "Action is ", action, "\n\n\n*********"
			######################################################
			if action == 'i':
				self.t_agent = {'ip':pkt['srcip'],'mac':pkt['srcmac'],
								  'port':pkt['inport'],'msg':pkt['msg'],
								  'ofproto':pkt['ofproto'], 'dp':pkt['dp']}
				print "T_AGENT Loaded"
			elif action == 'd':
				#Deleting flagged host policy
				print "Removing (",keyID,") from Policy Table"
				print "Existing Keys: ", self.policyTbl.keys()
				remove_keyID(keyID)
			elif action == 'r':
				print "Validating result"
				print "Key present?", self.policyTbl.has_key(keyID)
				if self.policyTbl.has_key(keyID):
					print "Test Result is: ", result
					if result == 'P':
						print "Removing keyID"
						remove_keyID(keyID)
					elif result =='F':
						print "Flagging Host: ", self.policyTbl[keyID]['ip']
						self.policyTbl[keyID]['stat'] = 'deny'
						srcmac, inport, srcip = get_fields(keyID)
						self.macTbl[srcmac].update({'stat':'deny'})
						self.portTbl[inport],self.ipTbl[srcip] ='deny','deny'
						self.update_TA(pkt, keyID,'e') #send edit message
						#Notify TA of update_TA(self,pkt, keyID)
					else: 
						print "An Error Occured"
			elif action is 'u':
				#This is more complicated it requires data not being stored
				#may need to add fields to policyTable. Maybe not. 
				pass
			elif action is 'a':
				#Acknowledge receipt
				pass
			else:
				print "No match"
			fields.update({'srcmac':self.cntrl['mac'], 'dstmac':pkt['srcmac']})
			fields.update({'srcip':self.cntrl['ip'], 'dstip':pkt['srcip']})
			fields.update({'ptype':'icmp','ethtype':0x0800, 'proto':1})
			fields['com'] = 'a,'+rcvData
			ops.update({'op':'craft', 'newport':pkt['inport']})
		return fields, ops
		



	#Crafts tailored ICMP message for trusted agent
	def update_TA(self,pkt, keyID, message):
		table = self.policyTbl[keyID]
		print 'Update Table: ', pkt['srcmac'],'->',keyID,'->',table['stat']
		print 'Update Table: ', table['srcmac'],'->',keyID,'->',table['stat']
		#print "Updating Trusted Agent"
		fields, ops = {},{}
		fields['keys'] = ['inport', 'srcip']
		fields.update({'dstip':self.t_agent['ip'], 'srcip':self.cntrl['ip']})
		fields.update({'dstmac':self.t_agent['mac'], 'srcmac':self.cntrl['mac']})
		fields.update({'dp':self.t_agent['dp'], 'msg':self.t_agent['msg']})
		fields.update({'inport':self.t_agent['port'],'ofproto':\
			self.t_agent['ofproto']})
		fields.update({'ptype':'icmp', 'ethtype':0x0800, 'proto':1, 'id':0})
		fields['com'] = message+','+table['srcmac']+','+str(table['inport'])+\
						','+str(table['passkey'])+','+table['stat']+\
						','+str(keyID)
		ops = {'hard_t':None, 'idle_t':None, 'priority':0, \
				   'op':'craft', 'newport':self.t_agent['port']}	
		self.install_field_ops(pkt, fields, ops)

	################################################################
	"""
	The following code controls the redirection of packets from their intended
	destination to our trusted agent. This occurs when a port is flagged. 
	"""
	################################################################
	#Create a method to inject a redirect anytime the sta4 IP address is
	
	#Check status of port and mac. 
	def check_net_tbl(self,pkt):
		mac, ip, port = pkt['srcmac'], pkt['srcip'], pkt['inport']
		print "(536) Check NetTbl: ", mac, ' & ', port,'->',self.macTbl.keys()
		if mac in self.macTbl.keys():
			print "Found: ", mac,'->', self.macTbl[mac]['stat']		 
			return self.macTbl[mac]['stat']
		elif port in self.portTbl.keys():
			print "Port ", port, " found in table."
			return self.portTbl[port]
		elif ip in self.ipTbl.keys():
			print "IP ", ip, " found in table." 
			return self.ipTbl[ip]
		else:
			print "Not Found: ", mac
			return 'new'	   
  
	#Redirect ICMP packets to trusted agent
	def Icmp_Redirect(self,pkt):
		print "Redirecting ICMP", pkt['srcmac'],'->',pkt['dstmac'],'||',self.t_agent['mac']
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



































	##Builds notification information for trusted agent and sends if via
	## self.update_TA (may want to combine these two definitions
	#def update_PolicyTbl(self,pkt,flag):
		#print "Update Policy: ", pkt['srcmac'],'->',flag
		##def notify_TA(self, pkt,status):
		#self.flagHost(pkt,flag)


	##Remove flag from policyTbl, macTbl, portTbl
	#def killFlag(self,pkt,keyID):
		#if self.policyTbl.has_key(keyID):
			#srcmac = self.policyTbl[keyID]['srcmac']
			#inport = self.policyTbl[keyID]['inport']
			#srcip =  self.policyTbl[keyID]['srcip']
			#if self.macTbl.has_key(srcmac):
				#self.macTbl.pop(srcmac)
			#if self.portTbl.has_key(inport):
				#self.portTbl.pop(inport)
			#if self.ipTbl.has_key(srcip):
				#self.ipTbl.pop(srcip)
			#self.policyTbl.pop(keyID)

	#def Arp_Poison(self,pkt):
		#print "Arp_Poison: ", pkt['srcmac'],'->',pkt['dstmac'],' or ',self.t_agent['mac']
		#fields, ops = self.default_Field_Ops(pkt)
		#if pkt['opcode'] != 2: 
			#fields['keys']=['srcmac', 'srcip', 'ethtype', 'inport']
			#fields['ptype'] = 'arp'
			#fields['ethtype'] = 0x0806 #pkt['ethtype']
			#print "Ethernet Type is : ", pkt['ethtype'], type(pkt['ethtype'])
			#fields['srcmac'] = self.t_agent['mac']
			#fields['dstmac'] = pkt['srcmac']
			#fields['srcip'] = pkt['dstip'] #self.t_agent['ip']
			#fields['dstip'] = pkt['srcip']
			#ops = {'hard_t':None, 'idle_t':None, 'priority':100, \
					   #'op':'craft', 'newport':pkt['inport']}
		#return fields,ops


	#def Tcp_Redirect(self,pkt):
		#print 'Redirecting TCP: ', pkt['srcmac'],'->',pkt['dstmac']
		#print "T Agent Mac/IP: ", self.t_agent['mac'], self.t_agent['ip']
		#fields, ops = self.default_Field_Ops(pkt)
		#fields['keys'] = ['inport', 'ethtype'] 
		#fields['dstmac'] = self.t_agent['mac']
		#fields['dstip'] = pkt['dstip'] #self.t_agent['ip']
		#fields['ethtype'] = pkt['ethtype']
		##fields['dstport'] = pkt['dstport']
		#ops['op'] = 'redir'
		#ops['newport'] = self.t_agent['port']
		#ops['priority'] = 100
		#ops['idle_t'] = 10
		#print "Fields: ", fields
		#return fields, ops


	#def ARP_after_DNS(self,pkt):
		#print 'Arp_after_DNS: ', pkt['srcmac'],'->',pkt['dstmac']
		#print "Output Port: ", self.macTbl[pkt['dstmac']]['port']
		#fields, ops = self.default_Field_Ops(pkt)
		#if pkt['dstmac'] == self.validNAT['ip']:
			#fields['srcmac'] = self.validNAT['mac']
		#else:
			#fields['srcmac'] = self.t_agent['mac']
		
		#fields['keys']=['srcmac', 'srcip', 'ethtype', 'inport']
		#fields['ptype'] = 'arp'
		#fields['opcode'] = 2
		#fields['ethtype'] = 0x0806 #pkt['ethtype']
		
		#fields['dstmac'] = pkt['dstmac']
		#fields['srcip'] = pkt['srcip'] #self.t_agent['ip']
		#fields['dstip'] = pkt['dstip']
		#ops = {'hard_t':None, 'idle_t':None, 'priority':100,
			   #'op':'craft', 'newport':self.macTbl[pkt['dstmac']]['port']}
		#return fields,ops
	
	#def spoofDNS(self,pkt):
		#fields, ops = self.default_Field_Ops(pkt)
		#print "Spoof DNS: ", pkt['srcip'],'->',pkt['dstip']
		#fields['keys']=['srcip', 'ethtype', 'inport']
		#fields['srcip']='75.75.75.75'
		#fields['dstip'] = pkt['dstip']
		#ops = {'hard_t':None, 'idle_t':None, 'priority':100,
			   #'op':'craft', 'newport':self.macTbl[pkt['dstmac']]['port']}
		#return fields, ops
	
	
	#def spoofTCP(self,pkt):
		#fields, ops = self.default_Field_Ops(pkt)
		#print "Spoof TCP: ", pkt['srcip'],'->',pkt['dstip']
		#fields['keys']=['srcmac', 'srcip', 'ethtype', 'inport']
		#fields['srcip']=self.t_agent['ip']
		#fields['dstip'] = pkt['dstip']
		#fields['dstmac'] = pkt['dstmac']
		#fields['srcmac'] = pkt['srcmac']
		#print fields
		#ops = {'hard_t':None, 'idle_t':None, 'priority':100,
			   #'op':'mod', 'newport':None}
		#return fields, ops		
	
	#def drop_ARP(self, pkt):
		#if pkt['dstip'] != self.t_agent['ip']:
			#fields, ops = self.default_Field_Ops(pkt)
			#fields['keys'] = ['inport', 'ethtype', 'proto']
			#fields['inport'] = pkt['inport']
			#fields['ethtype'] = pkt['ethtype']
			#fields['proto'] = pkt['proto']
			#ops['priority'] = 100
			#ops['op']='drop'
			#ops['idle_t'] = 120
			#print "(319) Droping ARP. Fields are: ", fields
		#return fields, ops


	#def spoofTCP(self,pkt):
		#fields, ops = self.default_Field_Ops(pkt)
		#print "Spoof TCP: ", pkt['srcip'],'->',pkt['dstip']
		#fields['keys']=['srcmac', 'srcip', 'ethtype', 'inport']
		#fields
		#fields['ptype'] = 'tcp'
		#fields['id'] = pkt['id']
		#fields['srcip']=self.t_agent['ip']
		#print fields['srcip']
		#fields['dstip'] = pkt['dstip']
		#fields['dstmac'] = pkt['dstmac']
		#fields['srcmac'] = pkt['srcmac']
		#fields['srcport'] = pkt['srcport']
		#fields['dstport'] = pkt['dstport']
		#fields['proto'] = pkt['proto']
		#fields['bits'] = pkt['bits']
		#fields['opt'] = pkt['opt']
		#print "Going to port ", self.macTbl[pkt['dstmac']]['port']
		#print "packet: ", pkt 
		#print "------------------------------------"
		#print "fields: ", fields
		
		#ops = {'hard_t':None, 'idle_t':None, 'priority':100,
			   #'op':'craft', 'newport':self.macTbl[pkt['dstmac']]['port']}
		#return fields, ops			   