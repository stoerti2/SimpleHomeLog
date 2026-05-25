package sudo_violations;
use strict;
use warnings;

sub new {
    my $class = shift;
    my $self = {};
    return bless $self, $class;
}

sub filter {
    my ($self, $log_entry) = @_;

    # Sicherheitsprüfung – undefinierte Werte ignorieren
    return undef unless defined $log_entry;

    if ($log_entry =~ /sudo:.*?FAILED|sudo:.*?authentication failure/) {
        return "SUDO_VIOLATION", $log_entry;
    }
    return undef;
}

1;
