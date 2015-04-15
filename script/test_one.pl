use 5.012;
use strict;
use warnings;

if (not @ARGV) {
  say "Parameter needed";
  exit 0
}

my $file = shift @ARGV;
my $rv = system("python",$file);

say '';
say '';
say "*"x50;
say '*'x10 . "Error detected by Perl's system" . '*'x10 if $rv;
say "*"x50;
