#!/usr/bin/perl -w
use Net::DNS::Dig;
use strict;
my $dig = new Net::DNS::Dig();
my $dom = shift or die "Usage: perl dig.pl <domain>";
my $dobj = $dig->for($dom, 'A'); #
print $dobj->sprintf; # print entire dig query response
print "CODE: ",$dobj->rcode(1),"\n"; # Dig Response Code
my %mx = Net::DNS::Dig->new()->for($dom,'MX')->rdata();
while(my($val,$server) = each(%mx)){
print "MX: ",$server," - ",$val,"\n";
}