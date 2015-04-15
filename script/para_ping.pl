use 5.012;
use strict;
use warnings;
use Time::HiRes qw//;


my $op = Time::HiRes::time();

my $td_count = 4;
my $tv = 33;

if(@ARGV and int($ARGV[0]) % 2 == 0)
{
    $td_count = int shift @ARGV;
}

if(@ARGV and int($ARGV[0]))
{
	$tv = int shift @ARGV;
}


my $seglen = 256 / $td_count;
print("Do it in $td_count:$seglen:->:$tv");

my @pids;
for my$seg(0..$td_count) {
	my$start = $seg*$seglen;
	$start +=1 if not $start;
	my$end = $seg*$seglen + $seglen - 1;
	
	my $pid = fork;
	die "$!:for $start..$end" if not defined($pid);
	unless ($pid) {
		for my$d ($start..$end) {
			my $dst = "192.168.1.$d";
			my $cmd = "ping $dst -l 30 -n 1 -w $tv";
			`$cmd`;
			#say $cmd;
			print '*' if not $?;
		}
		exit 0;
	}
	push @pids,$pid
}

#say "All Done For.";
for my$pid (@pids) {
	waitpid $pid,0
}

say "\n\nCompleted in ",Time::HiRes::time()-$op," second(s)";
