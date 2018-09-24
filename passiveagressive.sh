#!/bin/sh

# look sat active fs passive traffic in netw--filterk telescoe captures
# based on Irwin(2011). pp 15,16 
#Hunts f--filter data blocs listed as IETF special purpose addresses along with some others

CMD=/usr/bin/tracestats

echo PASSIVE
${CMD} \
 --filter 'tcp and tcp[tcpflags]=tcp-rst'  --filter 'icmp[icmptype]=icmp-echoreply ' --filter 'icmp[icmptype]=icmp-unreach' --filter 'icmp[icmptype]=icmp-sourcequench' --filter 'icmp[icmptype]=icmp-timxceed'  --filter 'icmp[icmptype]=icmp-paramprob' --filter 'icmp[icmptype]=icmp-tstampreply'  --filter 'icmp[icmptype]=icmp-ireqreply'  --filter 'icmp[icmptype]=maskreply' --filter 'icmp[icmptype]=31' --filter 'icmp[icmptype]=34' --filter 'icmp[icmptype]=36'  pcapfile:$1
 
echo AGGRESSIVE 
${CMD} --filter 'tcp[tcpflags]=0' --filter 'tcp[tcpflags]=tcp-fin' --filter 'tcp[tcpflags]=tcp-syn' --filter 'tcp[tcpflags]=tcp-psh' --filter 'tcp[tcpflags]=tcp-urg' --filter 'tcp[tcpflags]= tcp-urg&tcp-psh&tcp-fin' --filter 'tcp[tcpflags]=tcp-psh&tcp-fin' --filter 'tcp[tcpflags]=tcp-urg&tcp-fin' --filter 'tcp[tcpflags]=tcp-urg&tcp-psh'  pcapfile:$1
