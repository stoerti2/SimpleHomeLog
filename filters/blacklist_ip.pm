package blacklist_ip;
use strict;
use warnings;

my @blacklist;

sub init {
    my ($config) = @_;
    if (defined $config->{ip_list}) {
        @blacklist = split(/\s*,\s*/, $config->{ip_list});
    }
    # Alternative: load from file
    # if (defined $config->{list_file}) { ... }
}

sub filter {
    my ($line) = @_;
    foreach my $ip (@blacklist) {
        return 1 if $line =~ /\Q$ip\E/;
    }
    return 0;
}

1;
