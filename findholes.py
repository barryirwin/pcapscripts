#!/usr/bin/python
###dont work!/usr/bin/env python

#----------------------------------------------------------------#
# Searches for holes in pcap files 
# may be indicative of missing data merges or outages
# (c) 2018 Barry Irwin
#
#----------------------------------------------------------------#
import dpkt
# NB needs version 1.9.0 or greater 
if not (float(dpkt.__version__[0:3])>=1.9) :
	print 'ERROR: dpkt version >1.9.0 is required'
	sys.exit(2)
import time
import datetime
import sys

#sanity checking
if int(len(sys.argv)) < 3:
    print sys.argv[0] , 'requires two arguments <file> <gap interval (s)>'
    sys.exit(-1)


#do some base initialisation
timedelta=int(sys.argv[2])
tnow=0
tprev=0
tstart=0
pcount=0
gcount=0
gtime=0
glist={}

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

#print 'DEBUG: file data: ', f

pcap = dpkt.pcap.Reader(f)

#iterate over the file

for ts, buf in pcap:
# we only care about ts now
#    eth = dpkt.ethernet.Ethernet(buf)
#    ip = eth.data
#    tcp = ip.data
#    ip.
# take  the timestamp and  diff with previous
    #print ts
    tnow=ts
    if tprev==0:
        tprev=tnow
        tstart=tnow
        
    gap=int(tnow)-int(tprev)    
    #print 'DEBUG:',gap,gap > timedelta
    if gap > timedelta:
        #print 'DEBUG GAP ', int(tnow)-int(tprev) , 'secs exceeds ',timedelta
        gcount=gcount+1
        gtime=gtime+gap
        S=str(datetime.datetime.utcfromtimestamp(tprev))
        E=str(datetime.datetime.utcfromtimestamp(tnow))
        #print gcount,S,'->', E, '\t', gap, '\tpkt',pcount
        s=' '
        out=s.join((str(gcount),str(S),'->', E, '\t', str(gap), '\t',str(pcount)))
        #print 'DEBUG: ', gcount,out 
        glist[gcount]= out
        
    tprev=tnow
    pcount=pcount+1

f.close()
#now print out the contents

print '# File processed: ',sys.argv[1], '\n# Gap value: ',timedelta,'\n# Duration: ', str(datetime.datetime.utcfromtimestamp(tstart)), str(datetime.datetime.utcfromtimestamp(tnow))
print '# Packets processed: ',pcount
print '# Gaps found:',gcount, '\n', '# Secs missing: ', gtime , '\n', 

if gcount: # we have gaps
    print '# Gap\tStart\t\t\tEnd\t\t\t\tGaplen(s) Pkt#'
    for k in glist:
        print glist[k]
#else:
#    print '# NO GAPS Found, Awesome :-)'
    
