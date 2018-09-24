#!/usr/bin/python
###dont work!/usr/bin/env python

#----------------------------------------------------------------#
#  Takes two  files  and  Shows  set stuff
#	F1  !F2
#	F1 intersect F2
#	F1 !F1
# Useful to identify  Changes in traffic
# (c) 2018 Barry Irwin
#
#----------------------------------------------------------------#

import sys  #argv
import dpkt #packet processing
# NB needs version 1.9.0 or greater TODO add check
if not (float(dpkt.__version__[0:3])>=1.9) :
	print 'ERROR  dpkt version >1.9.0 is required'
	sys.exit(2) 
import time
import datetime
import socket

#sanity checking
if int(len(sys.argv)) < 3:
    print sys.argv[0] , 'requires two arguments <file1> <file2>'
    sys.exit(-1)


#do some base initialisation
# files to compare
telefile1=sys.argv[1]
telefile2=sys.argv[2]
pcount1=0
pcount2=0
#file 1 data
datasrc1=set()
datadport1=set()
datasport1=set()
dataUdport1=set()
dataUsport1=set()
# File 2 data
datasrc2=set()
datadport2=set()
datasport2=set()
dataUdport2=set()
dataUsport2=set()
#globals
#eth=0
#ip=0
#dumptofile
dump=1

def Genstat(pcapfile,datasrc,datadport,datasport,dataUdport,dataUsport):
  # do the data processing
  # print 'DEBUG :', pcapfile # should be dpkt.pcap
  pcount=0
  buggered=0
 # global eth
 # global ip
  for ts, buf in pcapfile: # assumes f is a pcap handle
	eth = dpkt.ethernet.Ethernet(buf)
	ip = eth.data # make assumptions because for this data its safe
	pcount=pcount+1
	datasrc.add(ip.src) # add src address to set    
	#socket.inet_ntoa(ip.src)
	#eth='0'

	if ip.p == 6 : #TCP
	  try:
        	tcp=ip.data
		datadport.add(int(tcp.dport))
		datasport.add(int(tcp.sport))
	  except:
		#print 'Shat the bed at packet ',pcount,'protocol ', ip.p,socket.inet_ntoa(ip.src),'->',socket.inet_ntoa(ip.dst)
		buggered=buggered+1
    	elif ip.p == 17: #UDP
          try:
                udp=ip.data
                dataUdport.add(int(udp.dport))
                dataUsport.add(int(udp.sport))
          except:
	        buggered=buggered+1
                # print 'Shat the bed at packet ',pcount,'protocol ', ip.p, socket.inet_ntoa(ip.src),'->',socket.inet_ntoa(ip.dst)
  return pcount

# --------------------------- Code starts --------------
#If compressed do gzip stuff  otherwise read normal
if (str(telefile1)[-3:]=='.gz'):
    import gzip
    f1=gzip.open(telefile1, 'rb')
elif (str(telefile1)[-4:]=='.bz2'):
    print '.bz2 is not currently supported only .gz'
    sys.exit(-1)
else:
    # open the file plain
    f1 = open(telefile1)
#Start with file 2
if (str(telefile2)[-3:]=='.gz'):
    import gzip
    f2=gzip.open(telefile2, 'rb')
elif (str(telefile2)[-4:]=='.bz2'):
    print '.bz2 is not currently supported only .gz'
    sys.exit(-1)
else:
    # open the file plain
    f2 = open(telefile2)



#print 'DEBUG: file data: ', f1 
pcap = dpkt.pcap.Reader(f1)
print 'Processing  File ',telefile1,' for statistics',
sys.stdout.flush()
pcount1=Genstat(pcap,datasrc1,datadport1,datasport1,dataUdport1,dataUsport1)
print ' Generation done'
f1.close()

pcap = dpkt.pcap.Reader(f2)
print 'Processing  File ',telefile2,' for statistics',
sys.stdout.flush()
pcount2=Genstat(pcap,datasrc2,datadport2,datasport2,dataUdport2,dataUsport2)
print ' Generation done'
f2.close()

#now print out the contents
print 'File1:' , telefile1, ' File2:',telefile2
print 'Packets Processed: File1' ,pcount1, 'File2', pcount2
print 'Uniq IP Sources :','File1:', len(datasrc1), 'File2:', len(datasrc2)
print 'TCP Src ports: ', 'File1:', len(datasport1), 'File2:', len(datasport2)
print 'TCP Dst ports: ','File1:', len(datadport1), 'File2:', len(datadport2)
print 'UDP Src ports: ''File1:', len(dataUsport1), 'File2:', len(dataUsport2)
print 'UDP Dst ports: ''File1:', len(dataUdport1), 'File2:', len(dataUdport2)

# now start with the delta stuff
diff1v2=datasrc1.difference(datasrc2)
diff2v1=datasrc2.difference(datasrc1)
commonsrc=datasrc1.intersection(datasrc2)
print '\n'
print 'Found ',len(diff1v2), ' IP sources in file 2 not in file 1'
print "%.2f" % (len(diff1v2)*100.0/len(datasrc2)), '% of File 2'
print 'Found ',len(diff2v1), ' IP sources in file 2 not in file 1'
print "%.2f" % (len(diff2v1)*100.0/len(datasrc1)), '% of File 1'
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

