#!/usr/bin/perl -w
use strict;
use LWP::UserAgent;
use LWP::Protocol::https;
my $usage = "Usage ./email_google.pl <domain>";
my $target = shift or die $usage;
my $ua = LWP::UserAgent->new;
my %emails = (); # unique
my $url = 'https://www.google.com/search?num=100&start=0&hl=en&meta=&q
=%40%22'.$target.'%22';
$ua->agent("Mozilla/5.0 (Windows; U; Windows NT 6.1 en-US;
rv:1.9.2.18) Gecko/20110614 Firefox/3.6.18");
$ua->timeout(10); # setup a timeout
$ua->show_progress(1); # display progress bar
my $res = $ua->get($url);
if($res->is_success){
my @urls = split(/url\?q=/,$res->as_string);
foreach my $gUrl (@urls){ # Google URLs
next if($gUrl =~ m/(webcache.googleusercontent)/i or not $gUrl =~
m/^http/);
$gUrl =~ s/&amp;sa=U.*//;
print $gUrl,"\n";
}
my @emails = $res->as_string =~ m/[a-z0-9_.-]+\@/ig;
foreach my $email (@emails){
if(not exists $emails{$email}){
print "Possible Email Match: ",$email,$target,"\n";
$emails{$email} = 1; # hashes are faster
}
}
}
else{
die $res->status_line;
}
