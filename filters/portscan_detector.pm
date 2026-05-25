package portscan_detector;
use strict;
use warnings;

sub new { bless {}, shift }

sub filter {
    my ($self, $log_entry) = @_;

    return undef unless defined $log_entry;

    if ($log_entry =~ /scan|port|nmap/i) {
        return "PORTSCAN", $log_entry;
    }
    return undef;
}

1;
