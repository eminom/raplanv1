use 5.012;
use strict;
use warnings;

defined(my $kw = shift @ARGV) or die "No parameter for me.";

die "Wrong word:$kw" if $kw !~ /^[\w+\d+]+$/;

opendir my $dir,'.' or die "Cannot open current directory.";

foreach my $file (readdir($dir)) {
	next unless $file =~ /\.py$/i;
	if (-f $file) {
		my @bingo;
		open my $rd,"<",$file or die "Cannot open $file.";
		my $lineno = 1;
		while (<$rd>) {
			chomp;
			if ( /(?:\bimport\s+$kw)|(?:\bfrom\s+$kw)/ ) {
				push @bingo,"line $lineno:$_"
			}
			$lineno++;
		}
		if(@bingo) {
			say "\"$file\":";
			foreach (@bingo) {
				say $_;
			}
			say'';
		}
		close $rd;
	}
}

closedir $dir;
