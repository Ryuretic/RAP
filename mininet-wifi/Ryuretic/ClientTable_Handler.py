import socket
import struct
import binascii
import sys, os

class ClientTable_Handler(object):

    def load_ip_match(self,keyID, match):
        tbl = open("/var/www/cgi-bin/RapTable.txt",'a')
        tbl.write(keyID+','+match+'\n')
        tbl.close()

    def validate_passkey(self,mac,passkey):
        tbl = open("/var/www/cgi-bin/ClientTable.txt").readlines()
        valid = False
        keyID = None
        for line in range(len(tbl)):
           if mac in tbl[line]:
               #print tbl[line]
               #print "Found MAC: ", mac
               if passkey in tbl[line]:
                   tbl_line = tbl[line].rstrip(' \t\r\n\0')
                   data = tbl_line.split(',')
                   keyID = data[4]
                   valid = True
        return valid, keyID

    def add_entry(self, rcvData):
        client_tbl = open("/var/www/cgi-bin/ClientTable.txt",'a')
        client_tbl.write(rcvData+'\n')
        client_tbl.close()

    def delete_entry2(self, mac,keyID):
        newTbl = []
        tbl = open("/var/www/cgi-bin/ClientTable.txt").readlines()
        for line in range(len(tbl)):
            if mac not in tbl[line] and tbl[line] != "\n":
                if keyID not in tbl[line]:
                    newTbl.append(tbl[line])
        client_tbl = open("/var/www/cgi-bin/ClientTable.txt",'w')
        for line in range(len(newTbl)):
            if newTbl[line] != '\n':
                client_tbl.write(newTbl[line])
        client_tbl.close()
        
    def delete_entry(self, keyID):
        newTbl = []
        tbl = open("/var/www/cgi-bin/ClientTable.txt").readlines()
        for line in range(len(tbl)):
            if tbl[line] != '\n':
                tbl_line = tbl[line].rstrip(' \t\r\n\0')
                data = tbl_line.split(',')
                if keyID != data[4]:
                    newTbl.append(tbl[line])
        client_tbl = open("/var/www/cgi-bin/ClientTable.txt",'w')
        for line in range(len(newTbl)):
            if newTbl[line] != '\n':
                client_tbl.write(newTbl[line])
        client_tbl.close()
        
    def foundKey(self, found):
        if found == True:
            print "Valid Key"
        else:
            print "Key not valid"

##    def send_revocation2(self,keyID):
##        print "Sending Revocation to controller"
##        try:
##            os.system('python ICMP_Revocation.py '+keyID)
##        except:
##            print "Message not sent"
        
    def send_revocation(self,keyID):
        client_tbl = open("/var/www/cgi-bin/RevTable.txt",'a')
        client_tbl.write(keyID+'\n')
        client_tbl.close()
        
def main():
    c_handle = ClientTable_Handler()
    rcvData = "00:00:00:00:00:04,3,mPtpYIcp,s,102"
    newmac = '00:00:00:00:00:04'
    passkey = 'mPtpYIcp'
    #c_handle.add_entry(rcvData)
    #c_handle.delete_entry(newmac,passkey)
    #c_handle.delete_entry('105')
    found, keyID = c_handle.validate_passkey(newmac,passkey)
    c_handle.foundKey(found)


if __name__=='__main__':
    main()
