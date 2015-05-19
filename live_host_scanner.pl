#!/usr/local/bin/perl
use strict;
use Net::Pcap;
use Net::Frame::Device;
use Net::Netmask;
use Net::Frame::Dump::Online;
use Net::ARP;
use Net::Frame::Simple;

my $err       = "";
my $dev       = pcap_lookupdev( \$err );                  # from Net::Pcap
my $devProp   = Net::Frame::Device->new( dev => $dev );
my $ip        = $devProp->ip;
my $gateway   = $devProp->gatewayIp;
my $netmask   = new Net::Netmask( $devProp->subnet );
my $mac       = $devProp->mac;
my $netblock  = $ip . ":" . $netmask->mask();
my $filterStr = "arp and dst host " . $ip;
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
		$ip,
		$ipts,
		$mac,
		"ff:ff:ff:ff:ff:ff",       # broadcast
		"request"
	);
}
until ( $pcap->timeout ) {
	if ( my $next = $pcap->next ) {    # frame according to $filterStr
		my $fref = Net::Frame::Simple->newFromDump($next);

		# we don't have to worry about the operation codes 1, or 2
		# because of the $filterStr
		print $fref->ref->{ARP}->srcIp, " is alive\n";
	}
}
END { print "Exiting\n"; $pcap->stop; }
