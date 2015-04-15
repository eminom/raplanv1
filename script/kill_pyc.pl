
use 5.012;
use strict;
use warnings;

opendir my$dir,'.' or die "Cannot open current directory.";

my $c = 0;
foreach my$file (readdir($dir)) {
	next if $file !~/\.pyc$/i;
	unlink $file or die "cannot remove $file:$!";
	say "Removing $file...";
	++$c;
}
say "$c pyc file(s) are removed.";

closedir $dir;
