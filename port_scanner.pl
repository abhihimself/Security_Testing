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
die "Usage: ./portscanner <target ip> <port-range> <tcp type> <my ip>
<timeout (seconds)> <pause time>" if ( !$ARGV[0] || $#ARGV != 5 );
my $target  = shift;    # target IP
my $pa      = shift;    # port Range "A".."B"
my $reqType = shift;    # request type, can be null
my $ip      = shift;    # my ip
my $pause   = shift;

my $myPort = 55378;     # my port
my $timeout *= 1000;
$pa =~ /([0-9]+)-([0-9]+)/;
my @portRange = ( $1 .. $2 );
my ( $ports, $open, $closed, $filtered ) = (0) x 4;

# most commonly used ports first:
my $common =
    "^(20|21|23|25|42|53|67|68|69|80|88|102|110|119|"
  . "135|137|138|139|143|161|162|389|443|445|464|500|"
  . "515|522|531|543|544|548|554|560|563|568|569|636|993|"
  . "995|1024|1234|1433|1500|1503|1645|1646|1701|1720|"
  . "1723|1731|1801|1812|1813|2053|2101|2103|2105|2500|"
  . "2504|3389|3527|5000|6665|6667|8000|8001|8002)\$";
my %winports = (
	135  => 'msrpc',
	139  => 'netbios-ssn',
	445  => 'microsoft-ds',
	554  => 'rtsp',
	2869 => 'icslap',
	5357 => 'wsdapi'
);
my %rtrports = (
	80   => 'http',
	443  => 'https',
	8080 => 'http-proxy',
	5000 => 'upnp',
	8888 => 'sun-answerbook'
);
my ( $win, $rtr, $oui ) = (0) x 2;    # Primitive OS detect
my ( $err, $net, $mask, $filter, $packet ) = "" x 5;
my $filterStr = "(src net " . $target . ") && (dst port " . $myPort . ")";
my $dev       = pcap_lookupdev( \$err );
pcap_lookupnet( $dev, \$net, \$mask, \$err )
  ;   #Determine the network number and netmask for the device specified in $dev
my $pcap = pcap_open_live( $dev, 1024, 0, 1000, \$err )
  ; #Returns a packet capture descriptor for looking at packets on the network pcap_open_live($dev, $snaplen, $promisc, $to_ms, \$err)
pcap_compile( $pcap, \$filter, $filterStr, 0, $mask )
  ;  #Compile the filter string contained in $filter_str and store it in $filter
pcap_setfilter( $pcap, $filter )
  ; #Associate the compiled filter stored in $filter with the packet capture descriptor $pcap
my %header;

########################MAIN###################################################

&sniffPacket($_)
  foreach ( shuffle( grep( /$common/, @portRange ) ) )
  ;    #grep all common port from port range array
&sniffPacket($_)
  foreach ( shuffle( grep( !/$common/, @portRange ) ) )
  ;    #After that non common ports
print "\n", $ports, " ports scanned, ", $filtered, " filtered, ", $open, "
open.\n";
print "OS Guess: ", ( $rtr > $win ) ? "Router Firmware\n" : "Windows OS\n"
  if ( $rtr > 0 || $win > 0 );
pcap_close($pcap);    # release resources
exit;

###############################################################################

sub sniffPacket {
	sleep $pause if ( $pause > 0 );    # pausing
	$ports++;                          # stats (all ports tried)
	my $port = shift;                  # to print it
	sendPacket($port);                 # send the TCP request
	while (1) {#We have given a always true loop because we don't know the response time of target 
		
		print "trying", "\n";
		
		my $pktRef = pcap_next_ex( $pcap, \%header, \$packet );#Reads the next available packet on the interface associated with packet descriptor $pcap
		print $pktRef,"\n";
		if ( $pktRef == 1 ) {          # we've got a packet:
			my $eth    = NetPacket::Ethernet::strip($packet);#Return the encapsulated data (or payload) contained in the ethernet packet
			my $ethdec = NetPacket::Ethernet->decode($packet);#Decode the raw packet data given and return an object containing instance data
			my $tcp    = NetPacket::TCP->decode( NetPacket::IP::strip($eth) );
			oui( $ethdec->{'src_mac'} ) if ( !$oui );  # return MAC manufacturer
			
			print $tcp->{'flags'},"\n";
			
			if ( $tcp->{'flags'} == 18 ) {
				$open++;
				print $port, "\topen\t";
				if    ( exists $rtrports{$_} ) { print $rtrports{$_}; $rtr++; }
				elsif ( exists $winports{$_} ) { print $winports{$_}; $win++; }
				else                           { print "unknown port." }
				print "\n";
			}
			elsif ( $tcp->{'flags'} == 20 ) {

				# closed port
			}
			last;    # found response, next ip
		}
		elsif ( $pktRef == 0 ) {
			$filtered++;    # filtered port from no response.
			last;           # found response, next ip
		}
		else {
			print "packets error!\n";#while loop will start the process again untill we get some valid packet
			
		}
	}
	return;
}

sub sendPacket {            # Target port = $_[0]
	my $targetPort = shift;
	my $packet     = Net::RawIP->new(
		{
			ip => {
				saddr => $ip,
				daddr => $target,
			},
			tcp => {
				source => $myPort,
				dest   => $targetPort,
			},
		}
	);    # craft packet
	$packet->set( { tcp => { $reqType => 1 } } ) if ( $reqType ne "null" );
	$packet->send;    # send packet
	return;
}

sub oui {
	my $mac = shift;
	( my $macBytes = $mac ) =~ s/([0-9a-f]{2})([0-9a-f]{2})([0-9a-f]{2})
([0-9a-f]{2})([0-9a-f]{2})([0-9a-f]{2})/$1:$2:$3:$4:$5:$6/;
	$oui = 1;         # make true
	$mac =~ s/([0-9a-f]{2})([0-9a-f]{2})([0-9a-f]{2}).*/$1\.$2\.$3/;
	open( OUI, "oui.txt" ) || die "please download oui.txt from IEEE.org\n";
	while ( my $l = <OUI> ) {
		if ( $l =~ /$mac/i ) {
			print $macBytes, " MAC Manufacturer: ";
			( my $v = $l ) =~ s/.*x\)\s+//;
			print $v, "\n";
			last;
		}
	}
	close OUI;
	return;
}
