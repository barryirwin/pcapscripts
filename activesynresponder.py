#!/usr/bin/env python

#----------------------------------------------------------------#
# Processes a TCPdump /lib pcap input file and splits input 
# 
# (c) 2018 Barry Irwin
# v 0.1
#----------------------------------------------------------------#
'''
Active response script  reports TCP syn packets received.

'''
import dpkt, pcap
# NB needs version 1.9.0 or greater 
if not (float(dpkt.__version__[0:3])>=1.9) :
	print 'ERROR: dpkt version >1.9.0 is required'
	sys.exit(2)

import sys
import socket


def __my_handler(ts,pkt):
    eth = dpkt.ethernet.Ethernet(pkt)
    ip = eth.data
    tcp= ip.data
    if tcp.flags &  dpkt.tcp.TH_RST :
        print 'RST Received'
        exit()

    if tcp.flags &  dpkt.tcp.TH_ACK : # We have payload
        dstip=socket.inet_ntoa(ip.dst) #string conversion
        srcip=socket.inet_ntoa(ip.src)
        if len(tcp.data) > 0:
            #shutdown
            print 'TCP-ACK [%s:%s -> %s:%s]  %s' %(srcip, tcp.sport , dstip, tcp.dport, len(tcp.data))
            myeth=dpkt.ethernet.Ethernet()
            myeth.src=eth.dst
            myeth.dst=eth.src
            myeth.type=eth.type
            myip=dpkt.ip.IP()
            myip.data=dpkt.tcp.TCP()
            myip.dst=ip.src
            myip.src=ip.dst
            myip.p=ip.p
            myip.data.sport=tcp.dport
            myip.data.dport=tcp.sport
            myip.data.seq = 9#0xdeadbeef
            myip.data.ack = tcp.seq+1
            myip.data.data ='OK'
            myip.len=len(myip.data)
            myeth.data=myip
            myip.data.flags= 0 | dpkt.tcp.TH_RST
            myip.ttl=69
            myeth.data=myip
            pc.inject(str(myeth),len(myeth))

    if len(tcp.data) == 0 :
        #send an ack
        # Now go about creating a response
        myeth=dpkt.ethernet.Ethernet()
        myeth.src=eth.dst
        myeth.dst=eth.src
        myeth.type=eth.type
        myip=dpkt.ip.IP()
        myip.data=dpkt.tcp.TCP()
        myip.dst=ip.src
        myip.src=ip.dst
        myip.ttl=27
        myip.p=ip.p
        myip.data.flags= 0 | dpkt.tcp.TH_ACK
        myip.data.sport=tcp.dport
        myip.data.dport=tcp.sport
        myip.data.seq = 8#0xdeadbeef
        myip.data.ack = tcp.seq+1
        myip.data.data ='OK'
        myip.len=len(myip.data)
        myeth.data=myip
        pc.inject(str(myeth),len(myeth))


    if tcp.flags &  dpkt.tcp.TH_SYN :
        dstip=socket.inet_ntoa(ip.dst) #string conversion
        srcip=socket.inet_ntoa(ip.src)
        print 'TCP-SYN [%s:%s -> %s:%s]' %(srcip, tcp.sport , dstip, tcp.dport)
        # Now go about creating a response
        myeth=dpkt.ethernet.Ethernet()
        myeth.src=eth.dst
        myeth.dst=eth.src
        myeth.type=eth.type
        myip=dpkt.ip.IP()
        myip.data=dpkt.tcp.TCP()
        myip.dst=ip.src
        myip.src=ip.dst
        myip.ttl=27
        myip.p=ip.p
        myip.data.flags= 0 | dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK
        myip.data.sport=tcp.dport
        myip.data.dport=tcp.sport
        myip.data.seq = 1#0xdeadbeef
        myip.data.ack = tcp.seq+1
        myip.data.data =''
        myip.len=len(myip.data)
        myeth.data=myip
        pc.inject(str(myeth),len(myeth))

    '''
    fin_flag = ( tcp.flags & dpkt.tcp.TH_FIN ) != 0
    syn_flag = ( tcp.flags & dpkt.tcp.TH_SYN ) != 0
    rst_flag = ( tcp.flags & dpkt.tcp.TH_RST ) != 0
    psh_flag = ( tcp.flags & dpkt.tcp.TH_PUSH) != 0
    ack_flag = ( tcp.flags & dpkt.tcp.TH_ACK ) != 0
    urg_flag = ( tcp.flags & dpkt.tcp.TH_URG ) != 0
    ece_flag = ( tcp.flags & dpkt.tcp.TH_ECE ) != 0
    cwr_flag = ( tcp.flags & dpkt.tcp.TH_CWR ) != 0
    '''





pc = pcap.pcap(name="eth1",promisc=1)
'''
 name      -- name of a network interface or dumpfile to open,
                 or None to open the first available up interface
    snaplen   -- maximum number of bytes to capture for each packet
    promisc   -- boolean to specify promiscuous mode sniffing
    timeout_ms -- requests for the next packet will return None if the timeout
                  (in milliseconds) is reached and no packets were received
                  (Default: no timeout)
    immediate -- disable buffering, if possible
'''
pc.setfilter('tcp and dst port 8081')
print 'listening on %s: %s' % (pc.name, pc.filter)
pc.loop(__my_handler)
'''
cnt      -- number of packets to process;
                    0 or -1 to process all packets until an error occurs,
                    EOF is reached;
        callback -- function with (timestamp, pkt, *args) prototype
        *args    -- optional arguments passed to callback on execution
'''
