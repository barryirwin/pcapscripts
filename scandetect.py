#!/usr/bin/python
###dont work!/usr/bin/env python

#----------------------------------------------------------------#
#  Takeas a pcap file and preprocesses for detecting hosts that have targeted a
#  threshold of others on a given port
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
#Threshold to detecting
threshold=255
pcount1=0
#file 1 data
srchosts={}
candidates=set()
#dumptofile
dump=1

def counttargets(pcapfile,datasrc):
  '''
  Take the pcap and count the number of distinct hosts that arre targetted
   - List of sets
   - to be used later as input to the actual scanning
  '''
  pcount=0
  for ts, buf in pcapfile: # assumes f is a pcap handle
	eth = dpkt.ethernet.Ethernet(buf)
	ip = eth.data # make assumptions because for this data its safe
	pcount=pcount+1
	if ip.src in datasrc :
		datasrc[ip.src].add(ip.dst)
	else:
		datasrc[ip.src]=set()
		datasrc[ip.src].add(ip.dst)
  '''
  Returns a populated datastructure
  '''
  return pcount

def filterhosts(datasrc):
	'''
	Takes the datasource and filters it to create a list  of those hosts over the
	given threshold.  This is used for second pass filtering to store actual sequence of targets
	'''
	global threshold
	fhost=set()
	for hosts in datasrc:
		if len(datasrc[hosts]) > threshold:
			fhost.add(hosts)
		else:
			pass

	return fhost

def buildscans(inputset,pcapfile):
  '''
	Iterated though a set, and does stuff if a pcap host entry appears in this list.
  '''
  scandata={}
  pcount=0
  for ts, buf in pcapfile: # assumes f is a pcap handle
	eth = dpkt.ethernet.Ethernet(buf)
	ip = eth.data # make assumptions because for this data its safe
	pcount=pcount+1
	if ip.src in inputset : # src IP is a known scanner
		# need to turn stuff back to ints here
		if ip.src in scandata:
			target=socket.inet_ntoa(ip.dst).split('.')[3]
			t2=scandata[ip.src]
			if target in t2:
				pass # avoid where we have remnant packets comming in.
			else:
				scandata[ip.src].append(socket.inet_ntoa(ip.dst).split('.')[3])
		else:
			scandata[ip.src]=[]
			scandata[ip.src].append(socket.inet_ntoa(ip.dst).split('.')[3])
  '''
  Returns a populated datastructure
  '''
  return scandata

def printpattern(pattern):
	'''
	Prints out data
	'''
	# TEMP:
	templist=[]
	uniqlist={}
	for h in pattern:
		print socket.inet_ntoa(h), '->' ,
		x=','.join(pattern[h])
		if x in uniqlist:
			uniqlist[x]+=1
		else:
			uniqlist[x]=1

		print x

	print len(uniqlist) ,' Unique scanning patterns identified'


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
print 'Processing  File ',infile,' hunting for scanning activity',
sys.stdout.flush()
pcount1=counttargets(pcap,srchosts)
print 'done'
print ' First pass scanning candidate identification completed: ', pcount1, 'packets processed'
print ' Reprocessing Candidate List ',
candidates=filterhosts(srchosts) # only return hosts above threshold
print len(candidates) , ' candidates identified from', len(srchosts) , 'observed'
print (len(candidates)*100.0)/len(srchosts) , 'potential scanners'
# can free up memory
del srchosts
del pcap

'''
Start the logic of now reprocessing the pcapfile
'''
# Rewind files
f1.seek(0,0)
pcap2=dpkt.pcap.Reader(f1)
print 'Re-Processing  File ',infile,' extracting scanning patterns',
sys.stdout.flush()
scanpattern=buildscans(candidates,pcap2)
print ' done'
print len(scanpattern) ,' patterns  obtained.'
#safe to close file handle now
f1.close()
#print 'Preparing output ',
#printpattern(scanpattern)
#if (dump==1): #output data to files
print 'Writing Sources to files: ',
f= open(outfile+'_scans','w')
f.write('#SRCIPv4,->,scanseq'+'\n')
for h in scanpattern:
   f.write(socket.inet_ntoa(h)+'->'+','.join(scanpattern[h])+'\n')

f.close()
