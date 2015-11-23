#!/usr/bin/perl -w
use strict;
use Net::DNS;
use Data::Dumper;
my $dns = Net::DNS::Resolver->new;
my @subDomains =
  ( "admin", "admindoesntexist", "www", "mail", "download", "gateway" );
my $usage  = "perl domainbf.pl <domain name>";
my $domain = shift or die $usage;               #get the target domain name here
my $total  = 0;
dns($_)
  foreach (@subDomains)
  ;    #for each subdomain mentyioned in array. DNS subroutine is called.
print $total, " records tested\n";

sub dns {    # search sub domains:
	$total++;    # record count
	my $first_detection = 0;
	my $host_name =
	  shift . "." . $domain;    # construct hostname like admin.target.com
	my $dnsLookup = $dns->search($host_name);
	if ($dnsLookup) {
		foreach my $ip ( $dnsLookup->answer ) {
			if ( $ip->type eq 'A' and $first_detection < 1 ) { #Just A records. Why we are collecting A records only explain here
				print $host_name,": ",$ip->address,"\n"; # just the IP
				$first_detection++;
			}
			else {
				return;
			}

		}
	}
	return;
}

