#!/usr/bin/perl -w
#Net::Whois::Raw module
#to interact with the American Registry for Internet Numbers (ARIN) database for
#an IP address:
use strict;
use Net::Whois::Raw;

die "Usage: perl netRange.pl <IP Address>" unless $ARGV[0];
foreach(split(/\n/,whois(shift))){
print $_,"\n" ;#if(m/^(netrange|orgname)/i);
}