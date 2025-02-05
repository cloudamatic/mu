# BEGIN COPYRIGHT BLOCK
# Copyright (C) 2007 Red Hat, Inc.
# All rights reserved.
#
# License: GPL (version 3 or any later version).
# See LICENSE for details. 
# END COPYRIGHT BLOCK
#

package SetupDialogs;

use strict;

use DialogManager;
use Setup;
use Dialog;
use Sys::Hostname;
use DSUtil;

my $welcome = new DialogYesNo (
    $EXPRESS,
    ['dialog_welcome_text', 'brand', 'brand'],
    1,
    sub {
        my $self = shift;
        my $ans = shift;
        my $res = $self->handleResponse($ans);
        if ($res == $DialogManager::NEXT) {
            $res = $DialogManager::ERR if (!$self->isYes());
        }
        return $res;
    },
    ['dialog_welcome_prompt'],
);

my $dsktune = new DialogYesNo (
    $EXPRESS,
    'dialog_dsktune_text',
    0,
    sub {
        my $self = shift;
        my $ans = shift;
        my $res = $self->handleResponse($ans);
        if ($res == $DialogManager::NEXT) {
            $res = $DialogManager::ERR if (!$self->isYes());
        }
        return $res;
    },
    ['dialog_dsktune_prompt']
);

$? = 0; # clear error condition
my $dsktune_output = `/usr/bin/dsktune`;
my $dsktune_result = $?;
$dsktune->{defaultIsYes} = $dsktune_result ? 0 : 1;
$dsktune->{text} = [$dsktune->{text}, $dsktune_output];

my $setuptype = new Dialog (
    $EXPRESS,
    'dialog_setuptype_text',
    sub {
        my $self = shift;
        return $self->{manager}->getType();
    },
    sub {
        my $self = shift;
        my $ans = shift;
        my $res = $DialogManager::SAME;
        if ($ans < $EXPRESS or $ans > $CUSTOM) {
            $self->{manager}->alert("dialog_setuptype_error");
        } else {
            $res = $DialogManager::NEXT;
            $self->{manager}->setType($ans);
        }
        return $res;
    },
    ['dialog_setuptype_prompt']
);

my $hostdlg = new Dialog (
    $TYPICAL,
    'dialog_hostname_text',
    sub {
        my $self = shift;
        return $self->{manager}->{inf}->{General}->{FullMachineName} ||
            hostname();
    },
    sub {
        my $self = shift;
        my $ans = shift;
        my $res = $DialogManager::NEXT;
        my $str;
        if ($str = checkHostname($ans, $self->{manager}->{res})) {
            my $promptary = ["dialog_hostname_warning", $str, $ans];
            my $yesorno = $self->{manager}->showPrompt($promptary, $self->{manager}->getText("no"));
            $res = DialogYesNo::handleResponse($self, $yesorno);
            if ($res == $DialogManager::NEXT) {
                $res = $DialogManager::SAME if (!DialogYesNo::isYes($self));
            }
        }
        $self->{manager}->{inf}->{General}->{FullMachineName} = $ans;
        return $res;
    },
    ['dialog_hostname_prompt']
);

# must verify that the user or uid specified by the user to run the server as
# is a valid uid
sub verifyUserChoice {
    my $self = shift;
    my $ans = shift;
    my $res = $DialogManager::NEXT;
    # convert numeric uid to string
    my $strans = $ans;
    if ($ans =~ /^\d/) { # numeric - convert to string
        $strans = getpwuid $ans;
        if (!$strans) {
            $self->{manager}->alert("dialog_ssuser_error", $ans);
            return $DialogManager::SAME;
        }
    }
    if ($> != 0) { # if not root, the user must be our uid
        my $username = getLogin;
        if ($strans ne $username) {
            $self->{manager}->alert("dialog_ssuser_must_be_same", $username);
            return $DialogManager::SAME;
        }
    } else { # user is root - verify id
        my $nuid = getpwnam $strans;
        if (!defined($nuid)) {
            $self->{manager}->alert("dialog_ssuser_error", $ans);
            return $DialogManager::SAME;
        }
        if (!$nuid) {
            $self->{manager}->alert("dialog_ssuser_root_warning");
        }
    }
    $self->{manager}->{inf}->{General}->{SuiteSpotUserID} = $ans;
    return $res;
}

# must verify that the given group is one of the groups the given user
# belongs to
sub verifyGroupChoice {
    my $self = shift;
    my $ans = shift;
    my $res = $DialogManager::NEXT;
    my ($dummy, $memstr);
    my $strgrp;
    my $numgrp;
    if ($ans =~ /^\d/) { # numeric
        $numgrp = $ans;
        ($strgrp, $dummy, $dummy, $memstr) = getgrgid $ans;
    } else {
        $strgrp = $ans;
        ($dummy, $dummy, $numgrp, $memstr) = getgrnam $ans;
    }

    if (!defined($strgrp) or !defined($numgrp)) {
        $self->{manager}->alert("dialog_ssgroup_error", $ans);
        return $DialogManager::SAME;
    }

    # get the user id, and then get the user's default group id
    my $uid = $self->{manager}->{inf}->{General}->{SuiteSpotUserID};
    my $usergid;
    if ($uid =~ /^\d/) { # numeric
        ($uid, $dummy, $dummy, $usergid, $dummy) = getpwuid $uid;
    } else { # string
        ($uid, $dummy, $dummy, $usergid, $dummy) = getpwnam $uid;
    }

    if ($numgrp == $usergid) {
        $self->{manager}->{inf}->{General}->{SuiteSpotGroup} = $ans;
    } elsif ($memstr) { # see if the user is in the member list
        if ($memstr =~ /\b$uid\b/) { # uid exactly matches one of the users in the member string
            $self->{manager}->{inf}->{General}->{SuiteSpotGroup} = $ans;
        } else { # no match
            $self->{manager}->alert("dialog_ssgroup_no_match",
                                   $self->{manager}->{inf}->{General}->{SuiteSpotUserID},
                                   $ans, $memstr);
            $res = $DialogManager::SAME;
        }
    } else { # user not in group
        $self->{manager}->alert("dialog_ssgroup_no_user",
                                $self->{manager}->{inf}->{General}->{SuiteSpotUserID},
                                $ans);
        $res = $DialogManager::SAME;
    }
    return $res;
}

my $usergroup = new Dialog (
    $TYPICAL,
    'dialog_ssuser_text',
    sub {
        my $self = shift;
        my $index = shift;
        if ($index == 0) {
            my $username = $self->{manager}->{inf}->{General}->{SuiteSpotUserID};
            if (!$username) {
                if ($> == 0) { # if root, use the default user
                    $username = "dirsrv";
                } else { # if not root, use the user's uid
                    $username = getLogin;
                }
            }
            return $username;
        } else { # group
            my $groupname = $self->{manager}->{inf}->{General}->{SuiteSpotGroup};
            if (!$groupname) {
                if ($> == 0) { # if root, use the default group
                    $groupname = "dirsrv";
                } else { # if not root, use the user's gid
                    $groupname = getgrgid $(;
                }
            }
            return $groupname;
        }
    },
    sub {
        my $self = shift;
        my $ans = shift;
        my $index = shift;
        if ($index == 0) {
            return verifyUserChoice($self, $ans);
        } else {
            return verifyGroupChoice($self, $ans);
        }
    },
    ['dialog_ssuser_prompt'], ['dialog_ssgroup_prompt']
);


sub getDialogs {
    return ($welcome, $dsktune, $setuptype, $hostdlg, $usergroup);
}

sub getRegDialogs {
    return ($usergroup);
}

1;
