#!/usr/bin/perl -w
use strict;
use LWP::UserAgent;
use LWP::Protocol::https;
my $ua = LWP::UserAgent->new;

my $usage = "Usage ./google_plus.pl <target name>";

my $target = shift or die $usage;
$target =~ s/\s/+/g;#replace blank space with + sign

my $gUrl = 'https://www.google.com/search?safe=off&noj=1&sclient=psy-ab&q=intitle%3A"About+-+Google%2B"+"Works+at+'.$target.'"+site%3Aplus.google.com&oq=intitle%3A"About+-+Google%2B"+"Works+at+'.$target.'"+site%3Aplus.google.com';
$ua->agent("Mozilla/5.0 (Windows; U; Windows NT 6.1 en-US;
rv:1.9.2.18) Gecko/20110614 Firefox/3.6.18");
$ua->timeout(10); # setup a timeout
my $res = $ua->get($gUrl);
if($res->is_success){
foreach my $string (split(/url\?q=/,$res->as_string)){
next if($string =~ m/(webcache.googleusercontent)/i or not $string
=~ m/^http/);
$string =~ s/&amp;sa=U.*//;
print $string,"\n";
}
}
else{
die $res->status_line;
}
