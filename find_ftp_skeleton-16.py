# Find FTP skeleton program
# Name: your name here

import sys
from scapy.all import *

try:
    path = sys.argv[1]
except:
    print "ERROR: need path to pcap file"
    sys.exit(0)

packets = rdpcap(path)
count = 0
modes = []
bytess = 0
for pkt in packets: 
    try:
        if (pkt.dport == 21 or pkt.sport == 21) and pkt.haslayer(Raw):
            count += 1
            
            payload_ = pkt.load
            bytess += len(payload_)
            if payload_[:4] == 'USER':
                print "Username:"+payload_[4:]
            if payload_[:4] == 'PASS':
                print "Password:"+payload_[4:]
            if "Passive" in payload_:
                print "FTP PORTS :"+payload_[25:].replace("(",'').replace(')','')
                modes.append("Passive")
            if "Active" in payload_:
                modes.append("Active")
            
    except Exception, e:
        # no packet found with port 21 
        # comment out this line and replace with 'pass' if too much data
        # if len(packets) > 2000:
        #     pass
        # else:
        #     print "BAD: ", e
        pass

print str(count)+" ftp packets were found"
print "modes:"+",".join(list(set(modes)))
diff = len(packets) - count
print str(diff)+" non-ftp packets found"

print str(bytess) +" bytes transfered"
