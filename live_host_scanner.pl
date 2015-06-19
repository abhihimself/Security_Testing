#!/usr/local/bin/perl
use strict;
use Net::Pcap;
use Net::Frame::Device;
use Net::Netmask;
use Net::Frame::Dump::Online;#tcpdump like implementation, online mode
use Net::ARP;
use Net::Frame::Simple;
use Data::Dumper;
my $err = "";
my $dev = pcap_lookupdev( \$err )
  ; # from Net::Pcap Returns the name of a network device(e.g eth0) that can be used for further exploration
my $devProp = Net::Frame::Device->new( dev => $dev )
  ; #Get default values from system specified in dev. dev stands for network device.
my $ip       = $devProp->ip;
my $gateway  = $devProp->gatewayIp;
my $netmask  = new Net::Netmask( $devProp->subnet );
my $mac      = $devProp->mac;
my $netblock = $ip . ":" . $netmask->mask();
#Upto here we got network iformation about our own system 

#########################################################################################################################
my $filterStr = "arp and dst host " . $ip; #created an ARP filter to use.
my $pcap      = Net::Frame::Dump::Online->new(
	dev           => $dev,
	filter        => $filterStr,
	promisc       => 0,
	unlinkOnStop  => 1,
	timeoutOnNext => 10            # waiting for ARP responses
);
$pcap->start;

print "Gateway IP: ", $gateway, "\n", "Starting scan\n";

for my $ipts ( $netmask->enumerate ) {
	Net::ARP::send_packet(
		$dev,
		$ip, #device ip
		$ipts,#destination ip
		$mac,
		"ff:ff:ff:ff:ff:ff",       # broadcast
		"request" #arp operation
	);
	#print $ipts,"\n";
}
until ( $pcap->timeout ) {
	if ( my $next = $pcap->next ) {    # next frame filtered according to $filterStr 
		my $fref = Net::Frame::Simple->newFromDump($next);
#print Dumper $fref,"\n";
		# we don't have to worry about the operation codes 1, or 2
		# because of the $filterStr
		print $fref->ref->{ARP}->srcIp, " is alive\n";
	}
}
END { print "Exiting\n"; $pcap->stop; }
