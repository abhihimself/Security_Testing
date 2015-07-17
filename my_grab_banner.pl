#!/usr/bin/perl
use strict;
use IO::Socket::INET;

print "Enter target ip: ";
chomp( my $ip = <> );
print "Enter protocol to use: ";
chomp( my $protocol = <> );
print "Enter port range(Comma seperated):  ";
chomp( my @pa = split( /,/, <> ) );

#print @pa;
print "Enter timeour<in sec>: ";
chomp( my $time_out = <> );
my $request = "HEAD / HTTP/1.1\n\n\n\n";
my ( $sock, $connection_ok, $connection_fail );
$connection_ok = $connection_fail = 0;

foreach my $port (@pa) {
	eval {
		$sock = IO::Socket::INET->new(
			PeerAddr => $ip,
			PeerPort => $port,
			Proto    => $protocol,
		  )

	};
	if ($@) {
		print "Unable to create socket: $@","\n";$connection_fail++;
	}
	else {
		eval {
			$sock->send($request);
			while (<$sock>) {
				chomp $_;
				print $_,"\n";
			}
			print "\n";
		};
		if ($@) {
			print "Unable to send request on port $port: $@","\n";
			$connection_fail++;
		}
		else {
			print "Connection successfull on $port","\n";
			$connection_ok++;
		}

	}

}
close $sock;
my $total=$#pa+1;
print "Total ports tried:$total","\n";
print "Successfull Connections:$connection_ok","\n";
print "Unsuccessfull Connections:$connection_fail","\n";
