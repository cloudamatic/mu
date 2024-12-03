# BEGIN COPYRIGHT BLOCK
# This Program is free software; you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation; version 2 of the License.
# 
# This Program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License along with
# this Program; if not, write to the Free Software Foundation, Inc., 59 Temple
# Place, Suite 330, Boston, MA 02111-1307 USA.
# 
# Copyright (C) 2007 Red Hat, Inc.
# All rights reserved.
# END COPYRIGHT BLOCK
#

package ASDialogs;

use strict;

use DialogManager;
use Setup;
use Dialog;
use DSUtil;

my $asserveradmin = new Dialog (
    $SILENT, # hidden
    'none',
    sub {
        my $self = shift;
        my $id = $self->{manager}->{inf}->{admin}->{ServerAdminID} ||
            $self->{manager}->{inf}->{General}->{ConfigDirectoryAdminID};
        if (isValidDN($id)) {
            $id =~ s/^(.*)=.*/$1/;
        }
        $self->{manager}->{inf}->{admin}->{ServerAdminID} = $id;
        my $pwd = $self->{manager}->{inf}->{admin}->{ServerAdminPwd} ||
            $self->{manager}->{inf}->{General}->{ConfigDirectoryAdminPwd};
        $self->{manager}->{inf}->{admin}->{ServerAdminPwd} = $pwd;
        return $id;
    },
    sub {
        return $DialogManager::NEXT;
    },
    ['none']
);

my $asport = new Dialog (
    $TYPICAL,
    'dialog_asport_text',
    sub {
        my $self = shift;
        my $port = $self->{manager}->{inf}->{admin}->{Port};
        if (!defined($port)) {
            $port = 9830;
            $self->{manager}->{setup}->{asorigport} = $port;
        }
        if (!$self->{manager}->{setup}->{reconfigas}) {
            if (!portAvailable($port)) {
                $port = getAvailablePort();
            }
        }
        return $port;
    },
    sub {
        my $self = shift;
        my $ans = shift;
        my $res = $DialogManager::SAME;
        my $reconf = $self->{manager}->{setup}->{reconfigas};
        if ($ans !~ /\d+/) {
            $self->{manager}->alert("dialog_asport_error", $ans);
        } elsif (!$reconf && !portAvailable($ans)) {
            $self->{manager}->alert("dialog_asport_error", $ans);
        } else {
            $res = $DialogManager::NEXT;
            $self->{manager}->{inf}->{admin}->{Port} = $ans;
        }
        return $res;
    },
    ['dialog_asport_prompt']
);

my $ashostip = new Dialog (
    $CUSTOM,
    'dialog_ashostip_text',
    sub {
        my $self = shift;
        if (!defined($self->{manager}->{inf}->{admin}->{ServerIpAddress})) {
            $self->{manager}->{inf}->{admin}->{ServerIpAddress} = "0.0.0.0";
        }
        return $self->{manager}->{inf}->{admin}->{ServerIpAddress};
    },
    sub {
        my $self = shift;
        my $ans = shift;
        if ($ans && (length($ans) > 0)) {
            $self->{manager}->{inf}->{admin}->{ServerIpAddress} = $ans;
        } elsif (exists($self->{manager}->{inf}->{admin}->{ServerIpAddress})) {
            delete $self->{manager}->{inf}->{admin}->{ServerIpAddress};
        }
        return $DialogManager::NEXT;
    },
    ['dialog_ashostip_prompt']
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
            $self->{manager}->alert("dialog_assysuser_error", $ans);
            return $DialogManager::SAME;
        }
    }
    if ($> != 0) { # if not root, the user must be our uid
        my $username = getLogin;
        if ($strans ne $username) {
            $self->{manager}->alert("dialog_assysuser_must_be_same", $username);
            return $DialogManager::SAME;
        }
    } else { # user is root - verify id
        my $nuid = getpwnam $strans;
        if (!defined($nuid)) {
            $self->{manager}->alert("dialog_assysuser_error", $ans);
            return $DialogManager::SAME;
        }
        if (!$nuid) {
            $self->{manager}->alert("dialog_assysuser_root_warning");
        }
    }
    $self->{manager}->{inf}->{admin}->{SysUser} = $ans;
    return $res;
}

my $assysuser = new Dialog (
    $CUSTOM,
    'dialog_assysuser_text',
    sub {
        my $self = shift;
        my $user = $self->{manager}->{inf}->{admin}->{SysUser};
        if (!defined($user)) {
            $user = $self->{manager}->{inf}->{General}->{SuiteSpotUserID};
        }
        if (!defined($user)) {
            if ($> == 0) { # if root, use the default user
                $user = "nobody";
            } else { # if not root, use the user's uid
                $user = getLogin;
            }
        }
        return $user;
    },
    sub {
        my $self = shift;
        my $ans = shift;
        return verifyUserChoice($self, $ans);
    },
    ['dialog_assysuser_prompt']
);

sub getDialogs {
    return ($asserveradmin, $asport, $ashostip, $assysuser);
}

1;
