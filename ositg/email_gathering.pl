#!/usr/bin/perl -w
use strict;
use LWP::UserAgent;
use LWP::Protocol::https;
use Data::Dumper;
#this program will help in social intelligence gathering 
#Different options 
my $usage = "Usage ./email_google.pl <domain>";
my $target = shift or die $usage;
my $ua = LWP::UserAgent->new;
my %emails = (); # unique

my $url = 'https://www.google.com/search?num=100&start=0&hl=en&meta=&q=%40%22'.$target.'%22';

$ua->agent("Mozilla/5.0 (Windows; U; Windows NT 6.1 en-US;
rv:1.9.2.18) Gecko/20110614 Firefox/3.6.18");
$ua->timeout(10); # setup a timeout
$ua->show_progress(1); # display progress bar
my $res = $ua->get($url);
if($res->is_success){
my @urls = split(/url\?q=/,$res->as_string); #split the string at /url\?q=/ and store it in to @urls
#google gives link inthis format <a href="http://www.google.com/url?q=http://www.yahoo.com/">Yahoo</a>
foreach my $gUrl (@urls){ # Google URLs
next if($gUrl =~ m/(webcache.googleusercontent)/i or not $gUrl =~
m/^http/); #ignore if it is not a http content or google cache data
#print "Before filter $gUrl","\n";
$gUrl =~ s/&amp;sa=U.*//; #replace &amp;sa=U<any data after that> with blank because that is data added by google.
print $gUrl,"\n";
}
my @emails = $res->as_string =~ m/[a-z0-9_.-]+\@.+\.com/ig;
print Dumper @emails;
=head
foreach my $email (@emails){
if(not exists $emails{$email}){
print "Possible Email Match: ",$email,$target,"\n";
$emails{$email} = 1; # hashes are faster
}
}
=cut
}
else{
die $res->status_line;
}
