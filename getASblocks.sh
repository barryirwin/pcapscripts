#!/bin/sh

# (c) 2020-2022 - Bary Irwin <bvi@moria.org>
# TODO
#   Data Validation tobe added

# This file uses whois to poll for IP records, and splits into a v4 and a v6 list

# USAGE
#   getASblock.sh AS1234
#
#  Outputs a list of  IPv4 and IPv6 netblocks, and a set of matchign filters suitable for use with tcpdump -F (and other apps?)

# CHANGELOG
#  25/07/22 - added some argument validation
#  14/06/22 - extended to use radb.net for more accurate data
#  April 2020  - added filter generation
#  Jan 2020 - Initial revision

if [ -z "$1" ] ; #Test for null/sero length string
then
	echo This script requires an ASN to be passed as the argument eg $0 AS2018.
	exit -1
fi

TMP=`echo $1 | cut -c1-2`

if [ "${TMP}" = 'AS'  -o  "${TMP}" = 'as' ];
then
	continue
else
	echo The AS number must be in the format ASxxxxx eg AS0000
	exit -1
fi	

TMP=`echo $1 | cut -c3-`
#need to account for 32-bit AS values
# See https://www.iana.org/assignments/as-numbers/as-numbers.xhtml
if [ "${TMP}" -le 4200000000  -a  "${TMP}" -gt 0 ];
then
        continue
else
	echo "The AS number must be in the  range 1-65534 (16-bit) or 131072-4200000000 (32-bit)"
	echo "See: https://www.iana.org/assignments/as-numbers/as-numbers.xhtml"
        exit -1 
fi 

# This provides the most accurate responses
WHOISSVR=whois.radb.net
AS=$1


echo Processing Data for $AS
echo -n Retrieving route and netblock data from ${WHOISSVR} :
# use whois/nc to grab - nc allows for longer lists without truncation
# !g is for ip4 !6 for IPv6
echo "!g${AS}" | nc ${WHOISSVR} 43 | sed -e 's/ /\n/g' | grep -vE '^[A-Z]' | sort -n | uniq > $AS.ipv4
echo -n " v4"
echo "!6${AS}" | nc ${WHOISSVR} 43| sed -e 's/ /\n/g' | grep -vE '^[A-Z]' | sort -n | uniq > $AS.ipv6
echo " v6"

# Generate a tcpdump filter from the files above
# final sed filter removes the trailing or by nulling out the last match
echo Generating tcpdump filters
cat $AS.ipv4 | sed -e 's/^/src net /g' -e 's/$/ or/' -e '$s/or//' > $AS.v4filter
cat $AS.ipv6 | sed -e 's/^/src net /g' -e 's/$/ or/' -e '$s/or//' > $AS.v6filter
#important to filter on *src* net only not dst net, or net in general

v4blocks=`wc -l $AS.ipv4| awk '{print $1}'`
v6blocks=`wc -l $AS.ipv6| awk '{print $1}'`

echo Complete
echo $v4blocks IPv4 Netblocks found
echo $v6blocks IPv6 Netblocks found

echo The filters $AS.v4filter and $AS.v6filter can be used with the -F flag to tcpdump.
echo Lists of Netblocks are comtained in $AS.ipv4 and $AS.ipv6

exit 0

# NOTES and additional Code
#Method below works but reports significantly fewer blocks than the method used
## whois -h whois.afrinic.net -- '-i origin AS2018'
#whois -h $WHOISSVR -- '-i origin AS2018 ' > $$.tmp
#whois -i origin AS2018 > $$.tmp
#echo Generating lists and filters
#fgrep "route:" $$.tmp | sed -e 's/^route:\s*//g' > $AS.ipv4
#fgrep "route6:" $$.tmp | sed -e 's/^route6:\s*//g' > $AS.ipv6

# alternate methods
#use whois/nc to grab
# !g is for ip4 !6 for IPv6
# need to clean up non numeric addresses and scrub duplicates
#echo '!gas2018'|nc whois.radb.net 43 | sed -e 's/ /\n/g' | grep -vE '^[A-Z]' | sort -n | uniq > $AS.ipv4_2
#echo '!6as2018'|nc whois.radb.net 43| sed -e 's/ /\n/g' | grep -vE '^[A-Z]' | sort -n | uniq > $AS.ipv6_2


