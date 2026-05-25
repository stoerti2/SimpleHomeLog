package cron_filter;
use strict;
use warnings;

sub filter {
    my ($line) = @_;
    # Ignoriere typische Cron-Zeilen
    return 1 if $line =~ /CRON\[\d+\]/;
    return 0;
}

1;
