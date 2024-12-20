# BEGIN COPYRIGHT BLOCK
# Copyright (C) 2007 Red Hat, Inc.
# All rights reserved.
#
# License: GPL (version 3 or any later version).
# See LICENSE for details. 
# END COPYRIGHT BLOCK
#

package DialogManager;
use Exporter ();
@ISA       = qw(Exporter);
@EXPORT    = qw($BACK $SAME $NEXT $ERR);
@EXPORT_OK = qw($BACK $SAME $NEXT $ERR);

use Dialog;
use SetupLog;

# Dialog responses
$FIRST = -2; # go back to first prompt on a dialog
$BACK = -1; # go back to previous dialog
$SAME = 0; # reshow the same prompt or dialog
$NEXT = 1; # go to the next dialog
$ERR = 2; # fatal error

# The DialogManager controls the flow of the dialogs and contains context shared
# among all of the dialogs (resources, logs, current setup type, etc.)
# all of these are optional
sub new {
    my $type = shift;
    my $self = {};

    $self->{setup} = shift;
    $self->{res} = shift;
    $self->{type} = shift;

    $self->{log} = $self->{setup}->{log};
    $self->{inf} = $self->{setup}->{inf};

    $self = bless $self, $type;

    return $self;
}

sub getType {
    my $self = shift;
    return $self->{type};
}

sub setType {
    my $self = shift;
    $self->{type} = shift;
}

sub addDialog {
    my $self = shift;
    for my $dialog (@_) {
        $dialog->setManager($self);
        push @{$self->{dialogs}}, $dialog;
    }
}

sub resetDialog {
    my $self = shift;
    @{$self->{dialogs}} = ();
}

# see if the user answered with the special BACK answer
sub isBack {
    my $self = shift;
    my $ans = shift;

    if (!$ans) {
        return 0;
    }

    # the word "back"
    if ($ans =~ /^\s*back\s*$/i) {
        return 1;
    }
    # a Ctrl-B sequence
    if ($ans eq '') {
        return 1;
    }

    return 0;
}

sub log {
    my $self = shift;
    if (!$self->{log}) {
        print @_;
    } else {
        $self->{log}->logMessage($INFO, "Setup", @_);
    }
}

sub getText {
    my $self = shift;
    return $self->{res}->getText(@_);
}

sub handleError {
    my $self = shift;
    my $msg = $self->{res}->getText('setup_err_exit');
    $self->{log}->logMessage($FATAL, "Setup", $msg);
}

sub showText {
    my $self = shift;
    my $msg = shift;
    my $text = $self->getText($msg);
    print "\n", ("=" x 78), "\n";
    # display it,
    print $text;
    # log it
    $self->log($text);
}

sub showPrompt {
    my $self = shift;
    my $msg = shift;
    my $defaultans = shift;
    my $ispwd = shift;

    my $text = $self->getText($msg);
    # display it,
    print $text;
    # log it
    $self->log($text . "\n");
    # display the default answer
    if ($defaultans) {
        print " [$defaultans]";
    }
    print ": ";
    # if we are prompting for a password, disable console echo
    if ($ispwd) {
        system("/bin/stty -echo");
    }
    # read the answer
    my $ans = <STDIN>;
    # if we are prompting for a password, enable console echo
    if ($ispwd) {
        system("/bin/stty echo");
        print "\n";
    }
    chop($ans); # trim trailing newline

    # see if this is the special BACK response, and finish if so
    if ($self->isBack($ans)) {
        $self->log("BACK\n");
        return $ans;
    }

    if (!length($ans)) {
        $ans = $defaultans;
    }

    # log the response, if not a password
    if (!$ispwd) {
        $self->log($ans . "\n");
    }

    return $ans;
}

sub alert {
    my $self = shift;
    my $msg = $self->{res}->getText(@_);
    print $msg;
    $self->{log}->logMessage($WARN, "Setup", $msg);
}

sub run {
    my $self = shift;
    my $done;
    my $index = 0;
    my $incr = 1;
    my $rc = 0;

    while (!$done) {
        my $dialog = $self->{dialogs}->[$index];
        if ($dialog->isEnabled()) {
            my $resp = $NEXT;
            $resp = $dialog->run($incr);
            if ($resp == $BACK) {
                $incr = -1;
            } elsif ($resp == $NEXT) {
                $incr = 1;
            } elsif (($resp == $SAME) or ($resp == $FIRST)) {
                $incr = 0;
            } else {
                $self->handleError($resp);
                $done = 1;
                $rc = 1;
            }
        }
        $index += $incr;
        if ($index < 0) {
            $index = 0;
        } elsif ($index >= @{$self->{dialogs}}) {
            $done = 1;
        }
    }

    return $rc;
}

#############################################################################
# Mandatory TRUE return value.
#
1;
