#!/usr/bin/python
###dont work!/usr/bin/env python

#----------------------------------------------------------------#
#  Takes file and print out sources along with frequency count
# (c) 2018 Barry Irwin
#
#----------------------------------------------------------------#

import sys  #argv
import dpkt #packet processing
# NB needs version 1.9.0 or greater 
if not (float(dpkt.__version__[0:3])>=1.9) :
	print 'ERROR  dpkt version >1.9.0 is required'
	sys.exit(2) 
import time
import datetime
import socket

#sanity checking
if int(len(sys.argv)) < 3:
    print sys.argv[0] , 'requires two arguments <infile> <outfile_base>'
    sys.exit(-1)


#do some base initialisation
# files to compare
infile=sys.argv[1]
outfile=sys.argv[2]
pcount1=0
#file 1 data
datasrc1={}
#dumptofile
dump=1

def Genstat(pcapfile,datasrc):
  # do the data processing
  pcount=0
  for ts, buf in pcapfile: # assumes f is a pcap handle
	eth = dpkt.ethernet.Ethernet(buf)
	ip = eth.data # make assumptions because for this data its safe
	pcount=pcount+1
	if ip.src in datasrc :
		datasrc[ip.src]+=1
	else:
		datasrc[ip.src]=1    

  return pcount

# --------------------------- Code starts --------------
#If compressed do gzip stuff  otherwise read normal
if (str(infile)[-3:]=='.gz'):
    import gzip
    f1=gzip.open(infile, 'rb')
elif (str(infile)[-4:]=='.bz2'):
    print '.bz2 is not currently supported only .gz'
    sys.exit(-1)
else:
    # open the file plain
    f1 = open(infile)


#print 'DEBUG: file data: ', f1 
pcap = dpkt.pcap.Reader(f1)
print 'Processing  File ',infile,' for statistics',
sys.stdout.flush()
pcount1=Genstat(pcap,datasrc1)
print ' Generation done'
f1.close()


#now print out the contents
print 'File Processed:' , infile 
print 'Packets Processed:' ,pcount1
print 'Uniq IP Sources :', len(datasrc1)

if (dump==1): #output data to files
  print 'Writing Sources to files: ',
  f= open(outfile+'_src_cnt.csv','w')
  f.write('#SRCIPv4,PacketCnt'+'\n')
  for s in datasrc1:
        f.write(socket.inet_ntoa(s)+','+str(datasrc1[s])+'\n')
  f.close()
  print 'CSV, ',
  f= open(outfile+'_src.txt','w')
  for s in datasrc1:
        f.write(socket.inet_ntoa(s)+'\n')
  f.close()
  print 'src IPs only'



