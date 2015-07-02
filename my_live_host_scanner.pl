#!/usr/local/bin/perl
use strict;
use Net::Pcap;
use Net::Frame::Device;
use Net::Netmask;
use Net::Frame::Dump::Online;
use Net::ARP;
use Net::Frame::Simple;
use Data::Dumper;
################Declarations################################
my (
	$err,    $dev,    $dev_info, $my_ip,
	$my_mac, $subnet, $netmask,  $filterstr,
	$destip, $next,   $target_data, $gateway
);
$err = "";
############################################################

$dev      = pcap_lookupdev( \$err );
$dev_info = Net::Frame::Device->new( dev => "$dev" );
$my_ip    = $dev_info->ip;
$my_mac   = $dev_info->mac;
$subnet   = $dev_info->subnet;
$gateway= $dev_info->gatewayIp;
$netmask  = new Net::Netmask($subnet);

#all info about our own network is with us now
#Now start a capture with proper filter

$filterstr = "arp and dst host " . "$my_ip";
my $capture = Net::Frame::Dump::Online->new(
	dev           => $dev,
	timeoutOnNext => 10,
	promisc       => 0,
	unlinkOnStop  => 1,
	filter        => $filterstr
);
$capture->start();
print "Gateway IP: ", $gateway, "\n", "Starting scan\n";
#capture started
#now start sending arp broadcast

foreach $destip ( $netmask->enumerate ) {
	Net::ARP::send_packet(
		$dev,                   # Device
		$my_ip,                 # Source IP
		$destip,                # Destination IP
		$my_mac,                # Source MAC
		"ff:ff:ff:ff:ff:ff",    # Destinaton MAC
		"request"
	);

}


#request sent to all local network block
#now filter the resposnse
until ( $capture->timeout ) {
	if ( $next = $capture->next() ) {
		$target_data = new Net::Frame::Simple->newFromDump($next);

		#$target_data->print();
		print $target_data->ref->{ARP}->srcIp, " is alive\n"
		  ; #ref attribute gives info about all the layers then we extract layer of our need ARP in this case.it use Net::Frame::Layer internally

	}

}
END { print "Exiting\n"; $capture->stop; }

