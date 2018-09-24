#!/bin/sh
#Hunts for data blocs listed as IETF special purpose addresses along with some others
CMD=/usr/bin/tracestats
${CMD} \
--filter 'net 0.0.0.0/8' \
--filter 'net 10.0.0.0/8' \
--filter 'net 127.0.0.0/8' \
--filter 'net 169.254.0.0/16' \
--filter 'net 172.16.0.0/12' \
--filter 'net 192.0.0.0/24' \
--filter 'net 192.0.2.0/24' \
--filter 'net 192.88.99.0/24' \
--filter 'net 192.168.0.0/16' \
--filter 'net 198.18.0.0/15' \
--filter 'net 198.51.100.0/24' \
--filter 'net 203.0.113.0/24' \
--filter 'net 224.0.0.0/4' \
--filter 'net 240.0.0.0/4' \
--filter 'net 100.64.0.0/10' \
--filter 'net 128.66.0.0/16' \
$1
