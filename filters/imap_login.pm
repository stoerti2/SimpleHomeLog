package imap_login;
use strict;
use warnings;

sub filter {
    my ($line) = @_;
    # Ignorier typical imap login lines
    return 1 if $line =~ /imap-login: Login: user/;
    return 0;
}

1;
