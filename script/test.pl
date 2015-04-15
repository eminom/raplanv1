use 5.012;
use strict;
use warnings;
use Time::HiRes qw/usleep/;

my $testRes = "test_result.txt";

open my $log,">",$testRes
	or die "Cannot open log file:$testRes.";
	
opendir my$dir,'.' 
	or die "cannot read current directory:$!";

my @allfiles = readdir $dir;
my @testfiles = grep {$_ =~  /^(?:test_.*\.py)|(?:co.*\.py)$/i} @allfiles;
my @pyfiles = grep {$_ =~ /\.py$/i} @allfiles;
my @obsolete_py = grep {$_ =~ /\.pyc$/i} @allfiles;

for (@obsolete_py) {
	say "Deleting $_...";
	unlink $_ or die "Cannot delete $_:$!";
}

say "\nPress any key to continue testing...>>";
<>;


my ($passed,$failed) =(0, 0);
my $start_time = Time::HiRes::time();
for my $testfile (@testfiles) {
      say "Processing $testfile...";
      #usleep(1000*1000);
      my $thisStart = Time::HiRes::time();
	system 'python',$testfile;

	$? ? ++$failed:++$passed;
	printf {$log} "%28s %-30s\tTest time:%18g\n","\"$testfile\"", "."x20 .  ($? ? "failed":"passed"), Time::HiRes::time()-$thisStart;
}
my $end_time = Time::HiRes::time();

say {$log} scalar @pyfiles," python file(s) detected.";
say {$log} scalar @testfiles," python file(s) are tested.";
say {$log} "$passed passed, $failed failed";
say {$log} '';
say {$log} $end_time - $start_time, " second(s) elpased.";
say {$log} "Test on ".localtime;

closedir $dir or die "cannot shutdown dir handle.";
close $log or die "Cannot shutdown log file.";

open $log,"<",$testRes
	or die "Cannot read $testRes";

local $/;
$/ = undef;
say "\n################"x3,"\n",<$log>;
close $log;

