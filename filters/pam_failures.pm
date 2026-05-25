package pam_failures;
use strict;
use warnings;

sub new { bless {}, shift }

sub filter {
    my ($self, $log_entry) = @_;

    return undef unless defined $log_entry;

    if ($log_entry =~ /pam_unix.*authentication failure/i) {
        return "PAM_FAILURE", $log_entry;
    }
    return undef;
}

1;
