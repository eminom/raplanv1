
#Flash ARP table

use 5.012;
use strict;
use warnings;
use diagnostics;

sub elicit_arp {
	my %dc;
	my $ref = undef;
    my $ip_pat = "(?<ip>(\\d{1,3}\\.){3}\\d{1,3})";
    my $mac_pat = "(?<mac>([\\da-fA-F]{2}-){5}[\\da-fA-F]{2})";
    my $entry_type = "(?<type>\\S+)";
    my $inter_no = "(?<interface_number>\\w+)";
    
	foreach( `arp -a`) {
		next if /^\s+$/;
		
		if( /.*:\s+$ip_pat[\s\-]+$inter_no/i ){
			$dc{$+{ip}} = [ $+{interface_number}, {} ];
			$ref = $dc{$+{ip}}[1];
			next;
		}
		
		if( /$ip_pat\s+$mac_pat\s+$entry_type/ ) {
			die if not defined($ref);
			$$ref{$+{ip}} = $+{mac} . ":" . $+{type};
		}
	}
	%dc;
}

sub print_arp {
	my $dc = shift;
	foreach my$intf_ip (keys %$dc) {
		say "[$intf_ip]:[${$dc}{$intf_ip}[0]]";
		my $entries = $$dc{$intf_ip}[1];
		foreach my$ip (keys %$entries) {
			say "\"$ip:$$entries{$ip}\"";
		}
	}
}

my %mac = elicit_arp;
print_arp \%mac;

