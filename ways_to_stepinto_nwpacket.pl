#!/usr/bin/perl
use strict;
use NetPacket::TCP;
use Net::Pcap;
use Data::Dumper;
my $err = "";
my $dev = pcap_lookupdev( \$err );

#pcap_open_live($dev, $snaplen, $promisc, $to_ms, \$err)
#Returns a packet capture descriptor for looking at packets on the network.
my $pcap = pcap_open_live( $dev, 65535, 1, 4000, \$err );
my $dumper = pcap_dump_open( $pcap, "output.cap" );
pcap_loop( $pcap, 25, \&cap, 0 );

#pcap_loop($pcap, $count, \&callback, $user_data)
#Read $count packets from the packet capture descriptor $pcap and call the perl function &callback with an argument of $user_data.
#If $count is negative, then the function loops forever or until an error occurs.
#Returns 0 if $count is exhausted, -1 on error, and -2 if the loop terminated due to a call to pcap_breakloop() before any packets were processed.
sub cap {
	my ( $user_data, $hdr, $pkt ) = @_;
	pcap_dump( $dumper, $hdr, $pkt )
	  ; #Dump the packet described by header %header and packet data $packet to the savefile associated with $dumper.
print Dumper $pkt; 
	# walk through each byte:
	my $src = sprintf( "%02x:%02x:%02x:%02x:%02x:%02x", unpack( "C6", $pkt ) );#src mac
	my $dst = sprintf(
		"%02x:%02x:%02x:%02x:%02x:%02x",    # 6 bytes #dst mac
		ord( substr( $pkt, 6,  2 ) ),
		ord( substr( $pkt, 7,  2 ) ),
		ord( substr( $pkt, 8,  2 ) ),
		ord( substr( $pkt, 9,  2 ) ),
		ord( substr( $pkt, 10, 2 ) ),
		ord( substr( $pkt, 11, 2 ) )
	);

	# here we see different methods for byte stepping:
	my $type = hex( unpack( "x12 C2", $pkt ) );    # 2 bytes

	#my $type = unpack("x12 H4",$pkt);
	my $ttl = hex( unpack( "x22 C1", $pkt ) )
	  ;    # 1 byte C is unsigned char, xis null byte 22 times
	my $ipv    = sprintf( "%02x", ord( substr( $pkt, 14, 1 ) ) );    # 1 byte
	my $ipflag = sprintf( "%02x", ord( substr( $pkt, 20, 1 ) ) );    # 1 byte
	my $proto  = sprintf( "%02x", ord( substr( $pkt, 23, 1 ) ) );    # 1 byte
	my $srcIP  = join ".",
	  unpack( "x26 C4", $pkt )
	  ;    # 26 (a repeat count)null bytes, 4 IP bytes, trunc
	my $dstIP = join ".",
	  unpack( "x30 C4", $pkt )
	  ;    # 30 (a repeat count)null bytes, 4 IP bytes, trunc
	my $srcPort = hex(
		"0x" . unpack( "H4", substr( $pkt, 34, 1 ) . substr( $pkt, 35, 1 ) ) );
	my $dstPort = hex(
		"0x" . unpack( "H4", substr( $pkt, 36, 1 ) . substr( $pkt, 37, 1 ) ) );
	my $tcpFlag = sprintf( "%02x", ord( substr( $pkt, 47, 1 ) ) );
	my $tcpBin = sprintf( "%08b", $tcpFlag );
	print $src, " -> ", $dst, " Type:", $type, " TTL:", $ttl, " IPV:", $ipv,
	  " IPFLAG:", $ipflag, " PROTO:", $proto, " SRCIP:", $srcIP, "
DSTIP:", $dstIP, " SRCPORT:", $srcPort, " DSTPORT:", $dstPort, " TCPFLAG:
", $tcpFlag, ":", $tcpBin, "\n";
}

END {
	pcap_close($pcap);
	pcap_dump_close($dumper);
	print "Exiting.\n";
}
