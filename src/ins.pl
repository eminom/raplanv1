use 5.012;
use strict;
use warnings;

my $ins_pyfile = 'rap_setup.py';

if('--clean' ~~ @ARGV) {
	say 'Cleanup all.';
	system 'rmdir build /q/s';
	system 'rmdir dist/q/s';
}
elsif ('-b' ~~ @ARGV or '--build' ~~ @ARGV) {
	say 'Building RapLanV1  ~   eminem7409@163.com';
	say '>>>';
	system 'python',$ins_pyfile,'install';
	die "building error: return value is $?" if $?;
}
elsif ('--rebuild' ~~ @ARGV) {
	say 'Rebuilding all...';
	say ">>>";
	system 'rmdir build /q/s';
	system 'python',$ins_pyfile,'install';
	die "building error: return value is $?" if $?;
}
elsif ('--bdist' ~~ @ARGV) {
	say "Building binary setup package...";
	say '>>>';
	system "python $ins_pyfile bdist_wininst";
	die "Failed :$?" if $?;
	
	my $ts = join '_',split /\s+/,'' . localtime ;
	$ts =~ s{:}{p}g;
	say $ts;
	system "rar a raplanv1_$ts.rar -s -k dist -r";
	die "Failed :$?" if $?;
	system "rmdir dist /q/s";
	system "rmdir build /q/s";
	die "Failed to remove unpacked binary:$?" if $?;
	
}
else {
	say "Need parameter to perform building task.";
	#say "--build/--rebuild";
}
