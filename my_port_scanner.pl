#!/usr/local/bin/perl;
#Working-This module will send a TCP packet to the target ip:port. Then it will wait for response .
#After receving a successfull response it will decode the TCP Data and check the flag parameter.
#As disussed in book If value of flag is 18 means port is open.If it is 20 means it is closed.
#Similarly it will scan all the port range ,given by user , on target system
use strict;

# use diagnostics; # dev debug
use Net::Pcap;              # sniffing packets
use NetPacket::Ethernet;    # Assemble and disassemble ethernet packets.
use Net::RawIP
  ;    #Perl extension to manipulate raw IP packets with interface to libpcap
use NetPacket::TCP;
use NetPacket::IP;
use List::Util qw(shuffle);

my ( $target_ip, $port_range, $common_ports,$request_type,$own_ip,$dev,$err,$net, $mask ,$filter);
my %router_ports;
my %os_ports;
$target_ip  = <>;
$port_range = <>;
$request_type=<>;
$own_ip=<>;
my $pause=<>;
my $timeout=1000;
my $own_port=55378;
my $filter_str="(src net " . $target_ip. ") && (dst port " . $own_Port . ")";
#################################################################################33
$dev=pcap_lookupdev();
pcap_lookupnet($dev,\$net,\$mask,\$err);
my $pcap = pcap_open_live( $dev, 1024, 0, 1000, \$err );
pcap_compile($pcap,\$filter,\$filter_str,0,$mask);
pcap_setfilter($pcap,$filter);
##########################Main Logic#########################################
forach(@)
sniff_packet();
###############################################################################
sub sniff_packet{
	
	
	
}






