package local_mails;
use strict;
use warnings;

sub filter {
    my ($line) = @_;
    # Ignore mails from local root user
    return 1 if ($line =~ /from=<root\@XXXXXXXX\.online-server\.cloud>/);
    return 1 if ($line =~ /to=root, ctladdr=root/);
    return 0;
}

1;
