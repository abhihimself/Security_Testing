#!/usr/bin/perl
#If the line begins with any
#character that is not a backslash, it is a group name. Otherwise, if the line begins
#with two backslashes, then the machine name followed by a backslash and a set of
#characters that are not backslashes, all are shared directories. If the directory name
#happens to end with the dollar symbol, $ , it is hidden or password protected.
use strict;
my @smbShares = `smbtree -N`;
my ( $protShares, $shareCount ) = (0) x 2;
foreach (@smbShares) {
	chomp( my $line = $_ );
	if (/^[0-9A-Z]/) { #if some number or capital letter is their
		print "GROUP: ", $line, "\n";
	}
	elsif (/\s+\\\\[^\\]+\\([^ ]+).*/) {
		print "\t", $1, "\n";
		$shareCount++;
		$protShares++ if ( $1 =~ /\$$/ );
	}
	elsif (/\s+\\\\([^\\]+)\n$/) {
		print "MACHINE: ", $1, "\n";
	}
}

END {
	print "\nShares: ", $shareCount, " Protected: ", $protShares, "\n";
}
