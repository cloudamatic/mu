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

package ConfigDSDialogs;

use strict;

use Sys::Hostname;
use DialogManager;
use Setup;
use Dialog;
use DSUtil;

use Mozilla::LDAP::API qw(ldap_explode_dn);

sub verifyConfigDSInfo {
    my $self = shift;
    my $url = $self->{manager}->{inf}->{General}->{ConfigDirectoryLdapURL};
    my $certdir;
    my @errs;
    if ($url =~ /^ldaps/) {
        if (!$self->{manager}->{inf}->{General}->{certdb} and
            !$self->{manager}->{inf}->{General}->{CACertificate}) {
            return ('dialog_configdsinfo_nocacert');
        }
        if (!$self->{manager}->{inf}->{General}->{certdb}) {
            (@errs) = AdminUtil::importCACert($self->{manager}->{setup}->{configdir} . "/admin-serv",
                                              $self->{manager}->{inf}->{General}->{CACertificate});
            if (@errs) {
                return @errs;
            }
        }
    }
    my $conn = AdminUtil::getConfigDSConn($url,
                                          $self->{manager}->{inf}->{General}->{ConfigDirectoryAdminID},
                                          $self->{manager}->{inf}->{General}->{ConfigDirectoryAdminPwd},
                                          $self->{manager}->{setup}->{configdir}, \@errs);
    if (@errs or !$conn) {
        $conn->close() if ($conn);
        return @errs if (@errs);
        return ('dialog_configdsinfo_unreachable', $url);
    }

    (@errs) = AdminUtil::verifyAdminDomain($conn, $url,
                                           $self->{manager}->{inf}->{General}->{AdminDomain});

    $conn->close();

    return @errs;
}

my $configdsinfo = new Dialog (
    $EXPRESS,
    'dialog_configdsinfo_text',
    sub {
        my $self = shift;
        my $index = shift;
        if ($index == 0) { # the url
            my $url = $self->{manager}->{inf}->{General}->{ConfigDirectoryLdapURL};
            if (!defined($url)) {
                my $host = $self->{manager}->{inf}->{General}->{FullMachineName} ||
                    hostname();
                my $port = $self->{manager}->{inf}->{slapd}->{ServerPort} || 389;
                if (!portAvailable($port)) {
                    $port = getAvailablePort();
                }
                my $suffix = "o=NetscapeRoot";
                $url = "ldap://$host:$port/$suffix";
            }
            return $url;
        } elsif ($index == 1) { # the id
            return $self->{manager}->{inf}->{General}->{ConfigDirectoryAdminID} ||
                "admin";
        } elsif ($index == 2) { # the password
            return undef;
        } elsif ($index == 3) { # admin domain
            my $admindomain = $self->{manager}->{inf}->{General}->{AdminDomain};
            if (!defined($admindomain)) {
                $admindomain = $self->{manager}->{inf}->{General}->{FullMachineName} ||
                    hostname();
                $admindomain =~ s/^[^\.]*\.//; # just the domain part
            }
            return $admindomain;
        } else { # the CA cert
            my $url = $self->{manager}->{inf}->{General}->{ConfigDirectoryLdapURL};
            my $cert = $self->{manager}->{inf}->{General}->{CACertificate};
            if (($url !~ /^ldaps/) or $self->{manager}->{inf}->{General}->{certdb} or
                ($cert =~ /^-----BEGIN CERTIFICATE-----/)) {
                # not using LDAPS, or already have a certdb - hide CA prompt
                $self->{prompts}->[4]->[2] = 1;
            } else {
                $self->{prompts}->[4]->[2] = 0; # unhide CA prompt
            }
            return $self->{manager}->{inf}->{General}->{CACertificate};
        }
    },
    sub {
        my $self = shift;
        my $ans = shift;
        my $index = shift;
        my $res = $DialogManager::SAME;
        if ($index == 0) {
            # validate URL?
            $self->{manager}->{inf}->{General}->{ConfigDirectoryLdapURL} = $ans;
            my $url = $self->{manager}->{inf}->{General}->{ConfigDirectoryLdapURL};
            if (($url !~ /^ldaps/) or $self->{manager}->{inf}->{General}->{certdb}) {
                # not using LDAPS, or already have a certdb - hide CA prompt
                $self->{prompts}->[4]->[2] = 1;
            } else {
                $self->{prompts}->[4]->[2] = 0; # unhide CA prompt
            }
            $res = $DialogManager::NEXT;
        } elsif ($index == 1) { # id
            $self->{manager}->{inf}->{General}->{ConfigDirectoryAdminID} = $ans;
            $res = $DialogManager::NEXT;
        } elsif ($index == 2) { # pwd
            my $test = $ans;
            if ($test) {
                $test =~ s/\s//g;
            }
            if (!$ans or (length($test) != length($ans))) {
                $self->{manager}->alert("dialog_configdsadmin_invalid");
            } else {
                $self->{manager}->{inf}->{General}->{ConfigDirectoryAdminPwd} = $ans;
                $res = $DialogManager::NEXT;
            }
        } elsif ($index == 3) { # admin domain
            $self->{manager}->{inf}->{General}->{AdminDomain} = $ans;
            $res = $DialogManager::NEXT;
        } else { # CA cert filename
            if ($ans && length($ans) &&
                ($ans !~ /^-----BEGIN CERTIFICATE-----/) && ! -f $ans) {
                $self->{manager}->alert("dialog_configdsinfo_ca_error", $ans);
            } else {
                $self->{manager}->{inf}->{General}->{CACertificate} = $ans;
                $res = $DialogManager::NEXT;
            }
        }

        if (($index == 4) && ($res == $DialogManager::NEXT)) {
            my (@text) = verifyConfigDSInfo($self);
            if (@text) {
                $self->{manager}->alert(@text);
                $self->{manager}->alert('dialog_configdsinfo_tryagain');
               $res = $DialogManager::FIRST;
            }
        }
        return $res;
    },
    ['dialog_configdsinfo_url_prompt'], ['dialog_configdsinfo_id_prompt'],
    ['dialog_configdsinfo_pwd_prompt', 1], ['dialog_configdsinfo_domain_prompt'],
    ['dialog_configdsinfo_ca_prompt']
);

my $regconfigdsinfo = new Dialog (
    $EXPRESS,
    'dialog_configdsinfo_text',
    sub {
        my $self = shift;
        my $index = shift;
        if ($index == 0) { # the url
            my $url = $self->{manager}->{inf}->{General}->{ConfigDirectoryLdapURL};
            if (!defined($url)) {
                my $host = $self->{manager}->{inf}->{General}->{FullMachineName} ||
                    hostname();
                my $port = $self->{manager}->{inf}->{slapd}->{ServerPort} || 389;
                if (!portAvailable($port)) {
                    $port = getAvailablePort();
                }
                my $suffix = "o=NetscapeRoot";
                $url = "ldap://$host:$port/$suffix";
            }
            return $url;
        } elsif ($index == 1) { # the id
            return $self->{manager}->{inf}->{General}->{ConfigDirectoryAdminID} ||
                "admin";
        } elsif ($index == 2 || $index == 3) { # the password
            return undef;
        } elsif ($index == 4) { # admin domain
            my $admindomain = $self->{manager}->{inf}->{General}->{AdminDomain};
            if (!defined($admindomain)) {
                $admindomain = $self->{manager}->{inf}->{General}->{FullMachineName} ||
                    hostname();
                $admindomain =~ s/^[^\.]*\.//; # just the domain part
            }
            return $admindomain;
        } else { # the CA cert
            my $url = $self->{manager}->{inf}->{General}->{ConfigDirectoryLdapURL};
            my $cert = $self->{manager}->{inf}->{General}->{CACertificate};
            if (($url !~ /^ldaps/) or $self->{manager}->{inf}->{General}->{certdb} or
                ($cert =~ /^-----BEGIN CERTIFICATE-----/)) {
                # not using LDAPS, or already have a certdb - hide CA prompt
                $self->{prompts}->[5]->[2] = 1;
            } else {
                $self->{prompts}->[5]->[2] = 0; # unhide CA prompt
            }
            return $self->{manager}->{inf}->{General}->{CACertificate};
        }
    },
    sub {
        my $self = shift;
        my $ans = shift;
        my $index = shift;

        my $res = $DialogManager::SAME;
        if ($index == 0) {
            # validate URL?
            $self->{manager}->{inf}->{General}->{ConfigDirectoryLdapURL} = $ans;
            my $url = $self->{manager}->{inf}->{General}->{ConfigDirectoryLdapURL};
            if (($url !~ /^ldaps/) or $self->{manager}->{inf}->{General}->{certdb}) {
                # not using LDAPS, or already have a certdb - hide CA prompt
                $self->{prompts}->[5]->[2] = 1;
            } else {
                $self->{prompts}->[5]->[2] = 0; # unhide CA prompt
            }
            $res = $DialogManager::NEXT;
        } elsif ($index == 1) { # id
            $self->{manager}->{inf}->{General}->{ConfigDirectoryAdminID} = $ans;
            $res = $DialogManager::NEXT;
        } elsif ($index == 2) { # pwd
            my $test = $ans;
            if ($test) {
                $test =~ s/\s//g;
            }
            if (!$ans or (length($test) != length($ans))) {
                $self->{manager}->alert("dialog_configdsadmin_invalid");
            } else {
                $self->{firstpassword} = $ans; # save for next index
                $res = $DialogManager::NEXT;
            }
        } elsif ($index == 3) { # verify second password
            if ($ans ne $self->{firstpassword}) {
                $self->{manager}->alert("dialog_configdsadmin_nomatch");
            } else {
                $self->{manager}->{inf}->{General}->{ConfigDirectoryAdminPwd} = $ans;
                $res = $DialogManager::NEXT;
            }
        } elsif ($index == 4) { # admin domain
            $self->{manager}->{inf}->{General}->{AdminDomain} = $ans;
            $res = $DialogManager::NEXT;
        } else { # CA cert filename
            if ($ans && length($ans) &&
                ($ans !~ /^-----BEGIN CERTIFICATE-----/) && ! -f $ans) {
                $self->{manager}->alert("dialog_configdsinfo_ca_error", $ans);
            } else {
                $self->{manager}->{inf}->{General}->{CACertificate} = $ans;
                $res = $DialogManager::NEXT;
            }
        }
        return $res;
    },
    ['dialog_configdsinfo_url_prompt'], ['dialog_configdsinfo_id_prompt'],
    ['dialog_configdsinfo_pwd_prompt', 1], ['dialog_configdsinfo_pwd2_prompt', 1],
    ['dialog_configdsinfo_domain_prompt', 0, 0], ['dialog_configdsinfo_ca_prompt']
);

my $configdsadmin = new Dialog (
    $EXPRESS,
    'dialog_configdsadmin_text',
    sub {
        my $self = shift;
        my $index = shift;
        my $id;
        if ($index == 0) { # return undef for password defaults
            $id = $self->{manager}->{inf}->{General}->{ConfigDirectoryAdminID};
            if (!defined($id)) {
                $id = "admin";
            } elsif (isValidDN($id)) { # must be a uid for this dialog
                my @rdns = ldap_explode_dn($id, 1);
                $id = $rdns[0];
            }
        }
        return $id;
    },
    sub {
        my $self = shift;
        my $ans = shift;
        my $index = shift;
        my $res = $DialogManager::SAME;
        if ($index == 0) { # verify DN
            if (($ans =~ /[\x00-\x20\x22\x2b\x2c\x3d\x5c\x7f\x80-\xff]/) && !isValidDN($ans)) {
                $self->{manager}->alert("dialog_configdsadmin_error", $ans);
            } else {
                $res = $DialogManager::NEXT;
                $self->{manager}->{inf}->{General}->{ConfigDirectoryAdminID} = $ans;
            }
        } elsif ($index == 1) { # verify initial password
            if ($ans =~ /[\x80-\xff]/) {
                $self->{manager}->alert("dialog_configdsadmin_invalid");
            } else {
                my $test = $ans;
                if ($test) {
                    $test =~ s/\s//g;
                }
                if (!$ans or (length($test) != length($ans))) {
                    $self->{manager}->alert("dialog_configdsadmin_invalid");
                } else {
                    $res = $DialogManager::NEXT;
                    $self->{firstpassword} = $ans; # save for next index
                }
            }
        } elsif ($index == 2) { # verify second password
            if ($ans =~ /[\x80-\xff]/) {
                $self->{manager}->alert("dialog_configdsadmin_invalid");
            } else {
                if ($ans ne $self->{firstpassword}) {
                    $self->{manager}->alert("dialog_configdsadmin_nomatch");
                } else {
                    $self->{manager}->{inf}->{General}->{ConfigDirectoryAdminPwd} = $ans;
                    $res = $DialogManager::NEXT;
                }
            }
        }
        return $res;
    },
    ['dialog_configdsadmin_prompt'], ['dialog_configdsadmin_pw1_prompt', 1], ['dialog_configdsadmin_pw2_prompt', 1]
);

my $configdsadmindomain = new Dialog (
    $TYPICAL,
    'dialog_configdsadmindomain_text',
    sub {
        my $self = shift;
        my $admindomain = $self->{manager}->{inf}->{General}->{AdminDomain};
        if (!defined($admindomain)) {
            $admindomain = $self->{manager}->{inf}->{General}->{FullMachineName} ||
                hostname();
            $admindomain =~ s/^[^\.]*\.//; # just the domain part
        }
        return $admindomain;
    },
    sub {
        my $self = shift;
        my $ans = shift;
        my $res = $DialogManager::SAME;
        if ($ans =~ /[\x00-\x20\x22\x2b\x2c\x3d\x5c\x7f\x80-\xff]/) {
            $self->{manager}->alert("dialog_configdsadmindomain_error", $ans);
        } elsif (isValidDN($ans)) {
            $self->{manager}->alert("dialog_configdsadmindomain_notadn", $ans);
        } else {
            $res = $DialogManager::NEXT;
            $self->{manager}->{inf}->{General}->{AdminDomain} = $ans;
        }
        return $res;
    },
    ['dialog_configdsadmindomain_prompt']
);

my $useconfigds = new DialogYesNo (
    $EXPRESS,
    'dialog_useconfigds_text',
    sub {
        my $self = shift;
        my $yes = $self->{"manager"}->getText("yes");
        my $nno = $self->{"manager"}->getText("no");
        my $ret = 0;
        if ((defined($self->{manager}->{inf}->{slapd}->{SlapdConfigForMC}) and
             ($yes =~ /^$self->{manager}->{inf}->{slapd}->{SlapdConfigForMC}/i)) or
            (defined($self->{manager}->{inf}->{slapd}->{UseExistingMC}) and
             !$self->{manager}->{inf}->{slapd}->{UseExistingMC})) {
            # we have to set up the directory server as the config ds
            $self->{manager}->{inf}->{slapd}->{SlapdConfigForMC} = "yes";
            $self->{manager}->{inf}->{slapd}->{UseExistingMC} = 0;
            $ret = 0; # explicitly create the config ds
        } elsif (defined($self->{manager}->{inf}->{General}->{ConfigDirectoryLdapURL})) {
            $ret = 1; # use an existing config ds and register the servers with that one
        } elsif (!defined($self->{manager}->{inf}->{slapd}->{SlapdConfigForMC}) and
                 !defined($self->{manager}->{inf}->{slapd}->{UseExistingMC})) {
            $ret = 0; # implicitly create the config ds
        } else {
            $ret = 1; # use an existing config ds and register the servers with that one
            if (exists($self->{manager}->{inf}->{slapd}->{SlapdConfigForMC})) {
                delete $self->{manager}->{inf}->{slapd}->{SlapdConfigForMC};
            }
            $self->{manager}->{inf}->{slapd}->{UseExistingMC} = 1;
        }
        return $ret;
    },
    sub {
        my $self = shift;
        my $ans = shift;
        my $res = $self->handleResponse($ans);
        if ($res == $DialogManager::NEXT) {
            if ($self->isYes()) {
                if (exists($self->{manager}->{inf}->{slapd}->{SlapdConfigForMC})) {
                    delete $self->{manager}->{inf}->{slapd}->{SlapdConfigForMC};
                }
                $self->{manager}->{inf}->{slapd}->{UseExistingMC} = 1;
                $configdsinfo->enable(); # use it
                $configdsadmin->disable();
                $configdsadmindomain->disable();
            } else {
                $self->{manager}->{inf}->{slapd}->{SlapdConfigForMC} = "yes";
                $self->{manager}->{inf}->{slapd}->{UseExistingMC} = 0;
                $configdsinfo->disable(); # ignore it
                $configdsadmin->enable();
                $configdsadmindomain->enable();
            }
        }
        return $res;
    },
    ['dialog_useconfigds_prompt'],
);

my $updatedialog = new DialogYesNo (
    $EXPRESS,
    'dialog_update_text',
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
    ['dialog_update_prompt'],
);


sub getDialogs {
    return ($useconfigds, $configdsinfo, $configdsadmin, $configdsadmindomain);
}

sub getRegDialogs {
    return ($regconfigdsinfo, $configdsadmindomain);
}

sub getUpdateDialogs {
    return ($updatedialog, $configdsinfo);
}

1;
