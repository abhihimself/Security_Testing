#!/usr/bin/perl
use strict;
use IO::Socket::INET;
my $usage = "./bg.pl <host> <protocol type> <comma separated ports>
<timeout seconds>\n";
die $usage unless my $host  = shift;
die $usage unless my $proto = shift;
die $usage unless my @ports = split( /,/, shift );
die $usage unless my $to    = shift;                 # time out (seconds)
my $conPorts=0;
my $errPorts=0;
my $sock;
PRTR: foreach my $port (@ports) {
	eval {
		local $SIG{ALRM} =
		  sub { $errPorts++; die; }; #local means save the current value of a globle variable and give it a local value in current scope.
		  	alarm($to);
		print "banner grabbing :", $port, "\n";
		if (
			$sock = IO::Socket::INET->new(
				PeerAddr => $host,
				PeerPort => $port,
				Proto    => $proto,
				Reuse=>1
			)
		  )
		{
			my $request = "HEAD / HTTP/1.1\n\n\n\n";
			$sock->send($request);
			print "\n";
			while (<$sock>) {
				chomp;
				print "
", $_, "\n";
			}
			print "\n";
			$conPorts++;
		}
		else {
			$errPorts++;
			print "couldn't connect to port: ", $port, "\n";
		}
		alarm(0);
		close $sock;
	};
	if ($@) {
		warn $port, " timeout exceeded\n";
		next PRTR;
	}
}

END {
	print ++$#ports, " tested, ", $conPorts, " connected successfully,
", $errPorts, " ports unsuccessful\n";
}
