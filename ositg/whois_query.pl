#!/usr/bin/perl -w
use strict;
use Net::Whois::Raw;

die "Usage: perl netRange.pl <IP Address>" unless $ARGV[0];
foreach(split(/\n/,whois(shift))){
print $_,"\n" ;#if(m/^(netrange|orgname)/i);
}