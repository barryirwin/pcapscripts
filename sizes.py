#!/usr/bin/python
###dont work!/usr/bin/env python

#----------------------------------------------------------------#
#  Takes a file and computes  packet size reports by protocol
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
    print sys.argv[0] , 'requires two arguments <input> <output>'
    sys.exit(-1)


#do some base initialisation
# files to compare
infile=sys.argv[1]
outfile=sys.argv[2]
pcount=0
tcpsize={}
udpsize={}
icmpsize={}

#dumptofile
dump=1

def spinner(x):
  # Spinner sets
  default = '-\|/'
  sys.stdout.write('\b')
  sys.stdout.write(default[x])
  #time.sleep(0.1)


def Genstats(pcapfile):
  # do the data processing
  # print 'DEBUG :', pcapfile # should be dpkt.pcap
  buggered=0
  p=0
  global pcount
  global tcpsize
  global udpsize
  global icmpsize
  for ts, buf in pcapfile: # assumes f is a pcap handle
	eth = dpkt.ethernet.Ethernet(buf)
	ip = eth.data # make assumptions because for this data its safe
	pcount=pcount+1

	if ip.p == 6 : #TCP
	  if ip.len in tcpsize :
		tcpsize[ip.len] += 1
	  else:
		tcpsize[ip.len] = 1
    	elif ip.p == 17: #UDP
	  if ip.len in udpsize :
                udpsize[ip.len] += 1
          else:
                udpsize[ip.len] = 1
	  
	elif ip.p == 1: #ICMP
	  if ip.len in icmpsize :
                icmpsize[ip.len] += 1
          else:
                icmpsize[ip.len] = 1
	'''	
	dospin=pcount/1000
	#print dospin,p,dospin>p
  	if (dospin>p):
		spinner(dospin % 4) #four states of spinner
  		sys.stdout.flush()
		p=pcount/100
	'''

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

pcap = dpkt.pcap.Reader(f1)
print 'Processing  File ',infile,' for statistics  ',
sys.stdout.flush()
Genstats(pcap)
print ' Generation done'
print pcount, ' packets processed'
f1.close()
'''
print 'Found ',len(commonsrc), ' common  sources '
print "%.2f" %  (len(commonsrc)*100.0/len(datasrc2|datasrc1)), '% of combined srcs'  # | joins sets

if (dump==1): #output data to files
  fbname=telefile1+'_'+telefile2 #basename
  print 'Writing Sources to files',
  f= open(fbname+'common'+'.txt','w')
  for s in commonsrc:
        f.write(socket.inet_ntoa(s)+'\n')
  f.close()
  print 'common',
  f= open(fbname+'f1'+'.txt','w')
  for s in diff1v2:
        f.write(socket.inet_ntoa(s)+'\n')
  f.close()
  print 'f1 only',
  f= open(fbname+'f2'+'.txt','w')
  for s in diff2v1:
        f.write(socket.inet_ntoa(s)+'\n')
  f.close()
  print 'f2 only'

# function for printing port data
def printportdata(a,b,msg):
  avb=a.difference(b)
  bva=b.difference(a)
  ab=a.intersection(b)
  print '\n'
  print 'Found ',len(avb), msg,' in file 2 not in file 1'
  print "%.2f" % (len(avb)*100.0/len(b)), '% of File 2'
  print 'Found ',len(bva), ' in file 2 not in file 1'
  print "%.2f" % (len(bva)*100.0/len(a)), '% of File 1'
  print 'Found ',len(ab), ' common ', msg
  print "%.2f" %  (len(ab)*100.0/len(a|b)), '% of combined srcs'  # | joins sets
  del avb
  del bva
  del ab

#tcpSRC
printportdata(datasport1,datasport2,'TCP source ports')
#tcpdst
printportdata(datadport1,datadport2,'TCP dest  ports')
#udpsrc
printportdata(dataUsport1,dataUsport2,'UDP source ports')
#UDPdst
printportdata(dataUdport1,dataUdport2,'UDP dest  ports')
'''

