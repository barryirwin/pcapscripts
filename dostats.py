#!/usr/bin/python
###dont work!/usr/bin/env python

#----------------------------------------------------------------#
# Produces Summary metadata for a capture 
# 
# (c) 2018 Barry Irwin
# v 0.1
#----------------------------------------------------------------#
import dpkt
import datetime
import time
import sys
import socket # used for socket.inet_ntoa
#sanity checking
if int(len(sys.argv)) < 3:
    print sys.argv[0] , 'requires two arguments <file> <gap interval (s)>'
    sys.exit(-1)

#If compressed do gzip stuff  otherwise read normal
if (str(sys.argv[1])[-3:]=='.gz'):
    import gzip
    f=gzip.open(sys.argv[1], 'rb')
elif (str(sys.argv[1])[-4:]=='.bz2'):
    print '.bz2 is not currently supported only .gz'
    sys.exit(-1)
else:
    # open the file plain
    f = open(sys.argv[1])

#do some base initialisation
protostats = { 1:0, 6:0, 17:0 }
srcstats={}
dststats={}
pcount=0
stime=int(time.time()) #epoch value
etime=0

# Read the pcap file and generate the following statistics:
# Packets by destingation - TCP/UDP/ICMP
# Packets by source - TCP/UDP/ICMP
# Packets by protocol - TCP/UDP/ICMP
# Packet Size Distribution
# Source ports
# Destination ports

#def pkt_destination(pkt):


pcap = dpkt.pcap.Reader(f)
#iterate over the file

for ts, buf in pcap:
    eth = dpkt.ethernet.Ethernet(buf)
    ip = eth.data # make assumptions because for this data its safe
    #src=socket.inet_ntoa(ip.src)
    #dst=socket.inet_ntoa(ip.dst)
    #protocol # ip.p is protocol 1 ICMP, 6, TCP, 17 UDP
    protostats[ip.p]=protostats[ip.p]+1    
    
    #SRC IP Address
    pcount=pcount+1
    if ip.src in srcstats: # or just src in srcstats
        srcstats[ip.src]=srcstats[ip.src]+1
    else:
        srcstats[ip.src]=1
    # DST IP Address
    if ip.dst in dststats :
        dststats[ip.dst]=dststats[ip.dst]+1
    else:
        dststats[ip.dst]=1
          
#     tcp = ip.data
#    ip.
# take  the timestamp and  diff with previous
    #print ts
    
    
#done reading so close    
f.close();    

etime=int(time.time()) #epoch value


for k in protostats:
  print k,protostats[k]

sys.stdout.flush()
       
for k in srcstats:
   print socket.inet_ntoa(k),srcstats[k]
   
sys.stdout.flush()        
for k in dststats:
   print socket.inet_ntoa(k),dststats[k]        


print 'Packets processed :' , pcount 
print 'Time taken : ' , int(etime)-int(stime), 'seconds'
print 'Output Time taken : ' ,int(time.time())-int(stime), 'seconds'
print 'avg rate : ' , pcount/(int(etime)-int(stime)), ' packets/seconds'
         
sys.stdout.flush()