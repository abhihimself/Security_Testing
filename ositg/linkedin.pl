#!/usr/bin/perl -w
#site:facebook.com "experience at target"
use strict;
use LWP::UserAgent;
use LWP::Protocol::https;
my $ua     = LWP::UserAgent->new;
my $usage  = "Usage ./googlepluslinkedin.pl <target name>";
my $target = shift or die $usage;
my $gUrl   = 'https://www.google.com/search?q=site:linkedin.
com+%22at+' . $target
  . '%22';    #intended dork is site:linkedin. com "at sliqbits"
my %lTargets = ();    # unique
$ua->agent(
	"Mozilla/5.0 (Windows; U; Windows NT 6.1 en-US;
rv:1.9.2.18) Gecko/20110614 Firefox/3.6.18"
);
$ua->timeout(10);     # setup a timeout
my $google = getUrl($gUrl);    # one and ONLY call to Google
foreach my $title ( $google =~
	m/\shref="\/url\?.*">[a-z0-9_.-]+\s?.b.at $target..b.\s-\slinked/ig )
{
	my $lRurl = $title;
	$title =~ s/.*">([^<]+).*/$1/;
	$lRurl =~ s/.*url\?.*q=(.*)&amp;sa.*/$1/;
	print $title, "-> " . $lRurl . "\n";
	my @ln = split( /\015?\012/, getUrl($lRurl) );
	foreach (@ln) {
		if (m/title="/i) {
			my $link = $_;
			$link =~ s/.*href="([^"]+)".*/$1/;
			next if exists $lTargets{$link};
			$lTargets{$link} = 1;
			my $name = $_;
			$name =~ s/.*title="([^"]+)".*/$1/;
			print "\t", $name, " : ", $link, "\n";
		}
	}
}

sub getUrl {
	sleep 1;    # pause...
	my $res = $ua->get(shift);
	if ( $res->is_success ) {
		return $res->as_string;
	}
	else {
		die $res->status_line;
	}
}
