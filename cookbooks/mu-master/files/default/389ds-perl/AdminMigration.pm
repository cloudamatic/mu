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

package AdminMigration;
require Exporter;
@ISA       = qw(Exporter);
@EXPORT    = qw(migrateAdminServer);
@EXPORT_OK = qw(migrateAdminServer);

# load perldap
use Mozilla::LDAP::Conn;
use Mozilla::LDAP::Utils qw(normalizeDN);
use Mozilla::LDAP::API qw(:constant ldap_url_parse ldap_explode_dn);

use Migration;
use AdminServer;
use AdminUtil;
use DSUtil;
use DSUpdate;
use SetupLog;

use File::Path;
use File::Spec;
# tempfiles
use File::Temp qw(tempfile tempdir);

use strict;

# This gathers all of the old information from the old
# scattered config files and updates the corresponding
# parameters in the $mig->{inf}
sub getOldFileInfo {
    my $mig = shift;

    # assume the config DS has already been migrated
    # we need to get our data out of there, and fix it
    # as needed
    my $oldAdmConf = getAdmConf($mig->{oldsroot} . "/admin-serv/config");
    $mig->{inf}->{admin}->{sie} = $oldAdmConf->{sie};
    $mig->{inf}->{admin}->{isie} = $oldAdmConf->{isie};
    if (defined($oldAdmConf->{ldapStart})) {
        $mig->{inf}->{admin}->{ldapStart} = $oldAdmConf->{ldapStart};
    }

    if (!defined($mig->{inf}->{General}->{FullMachineName}) or
        !defined($mig->{inf}->{admin}->{ServerIpAddress}) or
        !defined($mig->{inf}->{admin}->{Port})) {
        my $oldPset = getPset($oldAdmConf);
        if (!defined($mig->{inf}->{General}->{FullMachineName})) {
            $mig->{inf}->{General}->{FullMachineName} = $oldPset->{serverhostname};
        }
        if (!defined($mig->{inf}->{admin}->{ServerIpAddress})) {
            $mig->{inf}->{admin}->{ServerIpAddress} = $oldPset->{'configuration.nsserveraddress'};
        }
        if (!defined($mig->{inf}->{admin}->{Port})) {
            $mig->{inf}->{admin}->{Port} = $oldPset->{'configuration.nsserverport'};
        }
    }

    # need sie, isie, config ds url, admin id
    if (!defined($mig->{inf}->{General}->{ConfigDirectoryLdapURL})) {
        if (!open(DBSWITCH, $mig->{oldsroot} . "/shared/config/dbswitch.conf")) {
            $mig->msg('error_opening_dbswitch', $mig->{oldsroot} . "/shared/config/dbswitch.conf", $!);
            return 0;
        }
        while (<DBSWITCH>) {
            if (/^directory default (.*)$/) {
                $mig->{inf}->{General}->{ConfigDirectoryLdapURL} = $1;
            }
        }
        close(DBSWITCH);
    }
    if (!defined($mig->{inf}->{General}->{ConfigDirectoryAdminID})) {
        if (!open(ADMPW, $mig->{oldsroot} . "/admin-serv/config/admpw")) {
            $mig->msg('error_opening_ldapconf', $mig->{oldsroot} . "/admin-serv/config/admpw", $!);
            return 0;
        }
        while (<ADMPW>) {
            next if (/^#/);
            if (/^(.*):.*$/) {
                $mig->{inf}->{General}->{ConfigDirectoryAdminID} = $1;
            }
        }
        close(ADMPW);
    }
    if (!defined($mig->{inf}->{General}->{SuiteSpotGroup}) or
        !defined($mig->{inf}->{General}->{SuiteSpotUserID})) {
        if (!open(SSUSERS, $mig->{oldsroot} . "/shared/config/ssusers.conf")) {
            $mig->msg('error_opening_ssusersconf', $mig->{oldsroot} . "/shared/config/ssusers.conf", $!);
            return 0;
        }
        while (<SSUSERS>) {
            if (/^SuiteSpotGroup\s+(.*)$/) {
                if (!defined($mig->{inf}->{General}->{SuiteSpotGroup})) {
                    $mig->{inf}->{General}->{SuiteSpotGroup} = $1;
                }
            }
            if (/^SuiteSpotUser\s+(.*)$/) {
                if (!defined($mig->{inf}->{General}->{SuiteSpotUserID})) {
                    $mig->{inf}->{General}->{SuiteSpotUserID} = $1;
                }
            }
        }
        close(SSUSERS);
    }
    if (!defined($mig->{inf}->{General}->{AdminDomain})) {
        my @rdns = ldap_explode_dn($mig->{inf}->{admin}->{isie}, 1);
        $mig->{inf}->{General}->{AdminDomain} = $rdns[-2];
    }

    # the old admin server used to run as root - we cannot do that anymore
    # with Apache based admin server, so by default just use the SuiteSpotUserID
    # i.e. the same user id that the directory server uses
    # and if that is not defined, we'll just have to use the default
    if (!defined($mig->{inf}->{admin}->{SysUser})) {
        $mig->{inf}->{admin}->{SysUser} = $mig->{inf}->{General}->{SuiteSpotUserID} ||
            "nobody";
    }

    if (!defined($mig->{inf}->{General}->{SuiteSpotGroup})) {
        $mig->{inf}->{General}->{SuiteSpotGroup} = "nobody";
    }

    return 1;
}
     

# This is how we extract the sie and isie as the as entries are
# being added
sub migratecb {
    my ($context, $entry, $errs) = @_;

    my @arycontext = ($context);
    # always replace the tasks and commands with the new ones
    my $dn = $entry->getDN();
    if (($entry->getDN() =~ /^cn=Tasks/i) or
        ($entry->getDN() =~ /^cn=Commands/i)) {
        push @arycontext, 1; # means to delete any existing entries first
    }

    my $rc = check_and_add_entry(\@arycontext, $entry, $errs);

    return $rc;
}

# The config DS should have already been migrated, including the old
# admin server data.  We need to update that information.  Some of the
# fields no longer apply (userPassword, configuration.encryption.nsCertFile,
# configuration.encryption.nsKeyFile, serverRoot)
# some of the fields must be removed (any ssl2 fields)
# some of the fields must be changed (nsSuiteSpotUser)
sub migratePset {
    my $mig = shift;
    my $configdir = shift;
    my $inf = $mig->{inf};
    my @errs;

    my $conn = $mig->{inf}->{configdsconn};

    # add the Admin Server configuration entries
    my @ldiffiles = ("/usr/share/dirsrv/data/asmigrate.ldif.tmpl",
                     "/usr/share/dirsrv/data/21astasks.ldif.tmpl",
                     "/usr/share/dirsrv/data/22ascommands.ldif.tmpl"
                     );
    my @infs = getInfs("admin", "setup");

    my $mapper = new Inf("/usr/share/dirsrv/inf/asmigrate.map");

    $mapper = process_maptbl($mapper, \@errs, $inf, @infs);
    if (!$mapper) {
        $mig->msg(@errs);
        $mig->msg($FATAL, 'error_creating_asmigration_maptbl');
        return 0;
    }

    # update isie and sie
    getMappedEntries($mapper, \@ldiffiles, \@errs, \&migratecb, $conn);
    if (@errs) {
        $mig->msg(@errs);
        return 0;
    }

    my $localconf = "$configdir/local.conf";
    my $isnew;
    if (! -f $localconf) {
        $isnew = 1;
    }
    if (!open(LOCALCONF, ">$localconf")) {
        $mig->msg($FATAL, 'error_updating_localconf', $localconf, $!);
        return 0;
    }
    # now get the entries and write them to local.conf
    my $entry = $conn->search($inf->{admin}->{sie}, "sub", "(objectclass=*)");
    if (!$entry || $conn->getErrorCode()) {
        $mig->msg($FATAL, 'error_no_localconf_entries',
                  $inf->{admin}->{sie}, $localconf, $conn->getErrorString());
        close(LOCALCONF);
        return 0;
    }        
        
    while ($entry) {
        updateLocalConf($entry, $inf->{admin}->{sie}, \*LOCALCONF);
        $entry = $conn->nextEntry();
    }
    close(LOCALCONF);

    if ($isnew) {
        my $admConf = getAdmConf($configdir);
        my $uid = getpwnam $admConf->{sysuser};
        chmod 0600, "$localconf";
        chown $uid, -1, "$localconf";        
    }

    return 1;
}

sub updateconinfocb {
    my ($context, $entry, $errs) = @_;

    my @arycontext = ($context);
    # add or update all of the entries except for the UserDirectory
    my $dn = $entry->getDN();
    if (($entry->getDN() =~ /^cn=UserDirectory/i)) {
        return 1; # return true, continue
    }

    my $rc = check_and_add_entry(\@arycontext, $entry, $errs);

    return $rc;
}

# this updates any information in the configDS that pertains
# to the console being upgraded
sub updateConsoleInfo {
    my $mig = shift;
    my $configdir = shift;
    my $inf = $mig->{inf};
    my @errs;

    my $conn = $mig->{inf}->{configdsconn};

    if (@errs) {
        $mig->msg($FATAL, @errs);
        return 0;
    }

    # update the console info
    my @ldiffiles = ("/usr/share/dirsrv/data/02globalpreferences.ldif.tmpl"
                     );
    my @infs = getInfs("admin", "slapd", "setup");
    my $mapper = new Inf("/usr/share/dirsrv/inf/updateconsoleinfo.map");

    $mapper = process_maptbl($mapper, \@errs, $inf, @infs);
    if (!$mapper) {
        $mig->msg(@errs);
        $mig->msg($FATAL, 'error_creating_updateconsole_maptbl');
        return 0;
    }

    # update isie and sie
    getMappedEntries($mapper, \@ldiffiles, \@errs, \&updateconinfocb, $conn);
    if (@errs) {
        $mig->msg(@errs);
        return 0;
    }

    # now, copy over any customization entries
    my $basedn = "ou=Admin, ou=Global Preferences, ou=" .
        $inf->{General}->{AdminDomain} . ", o=NetscapeRoot";
    my $versents = $conn->search($basedn, "sub", "(objectclass=*)", 0, qw(* aci));
    if (!$versents) {
        $mig->msg($FATAL, 'error_migrating_console_entries', $basedn, $conn->getErrorString());
        return 0;
    }

    my @oldents = ();
    for ($versents; $versents; $versents = $conn->nextEntry()) {
        push @oldents, $versents;
    }

    for (@oldents) {
        my $olddn = $_->getDN();
        my $ver = getInfsVal('admin', 'ConsoleVersion', @infs);
        if (($olddn =~ /ou=(\d.\d)/) && ($1 ne $ver)) {
            my $newdn = $olddn;
            $newdn =~ s/ou=$1/ou=$ver/;
            my $newent = $_;
            $newent->setDN($newdn);
            $conn->add($newent);
            if ($conn->getErrorCode() == LDAP_SUCCESS) {
                debug(3, "Added new console customization entry $newdn\n");
            } elsif ($conn->getErrorCode() == LDAP_ALREADY_EXISTS) {
                debug(3, "Console customization entry $newdn already exists, skipping\n");
            } else {
                $mig->msg($FATAL, 'error_adding_console_entries', $newdn, $conn->getErrorString());
                return 0;
            }
        } else {
            debug(3, "Skipping entry $olddn - do not need to migrate it\n");
        }
    }

    return 1;
}

sub migrateSecurityFiles {
    my $mig = shift;
    my $configdir = shift;

    my $admConf = getAdmConf($configdir);
    my $sie = $admConf->{sie};
    my @rdns = ldap_explode_dn($sie, 1);
    my $inst = $rdns[0];
    my $rc = $mig->migrateSecurityFiles($inst, $configdir);
    my $haspinfile;
    if (-f $mig->{oldsroot} . "/admin-serv/config/password.conf") {
        if (system ("cp -p $mig->{oldsroot}/admin-serv/config/password.conf $configdir/pin.txt")) {
            $mig->msg('error_copying_passwordconf', "$mig->{oldsroot}/admin-serv/config/password.conf", $!);
            return 0;
        }
    }

    return 1;
}

sub updateConfFileSecInfo {
    my $mig = shift;
    my $configdir = shift;

    my $haspinfile;
    for (glob("$configdir/*")) {
        if (/pin\.txt$/) {
            $haspinfile = 1;
        }
    }

    # if the user has specified a pin file, we need to let nss.conf know
    if ($haspinfile) {
        if (!open(NSSCONF, "$configdir/nss.conf")) {
            $mig->msg('error_opening_nssconf', "$configdir/nss.conf", $!);
            return 0;
        }
        my @nssconf = <NSSCONF>;
        close(NSSCONF);
        # nss.conf is usually read-only
        chmod 0600, "$configdir/nss.conf";
        if (!open(NSSCONF, ">$configdir/nss.conf")) {
            $mig->msg('error_writing_nssconf', "$configdir/nss.conf", $!);
            chmod 0400, "$configdir/nss.conf";
            return 0;
        }
        my $found;
        for (@nssconf) {
            if (/^NSSPassPhraseDialog/) {
                $found = 1;
                $_ = "NSSPassPhraseDialog file:$configdir/pin.txt\n";
            }
            print NSSCONF $_;
        }
        if (!$found) {
            print NSSCONF "NSSPassPhraseDialog file:$configdir/pin.txt\n";
        }
        close(NSSCONF);
        chmod 0400, "$configdir/nss.conf";
    }

    # update console.conf with security info
    my $pset = getPset($configdir);
    if (defined($pset->{'configuration.nsserversecurity'}) and
        ($pset->{'configuration.nsserversecurity'} =~ /on/i)) {
        my $certname = $pset->{'configuration.encryption.rsa.nssslpersonalityssl'};
        my $clientauth = $pset->{'configuration.encryption.nssslclientauth'};
        if (!open(CONSOLECONF, "$configdir/console.conf")) {
            $mig->msg('error_opening_consoleconf', "$configdir/console.conf", $!);
            return 0;
        }
        my @consoleconf = <CONSOLECONF>;
        close(CONSOLECONF);
        if (!open(CONSOLECONF, "> $configdir/console.conf")) {
            $mig->msg('error_writing_consoleconf', "$configdir/console.conf", $!);
            return 0;
        }
        for (@consoleconf) {
            if (/^NSSEngine/) {
                $_ = "NSSEngine on\n";
            } elsif (/^NSSNickname/) {
                $_ = "NSSNickname $certname\n";
            } elsif (/^NSSVerifyClient/) {
                if ($clientauth =~ /on/) {
                    $_ = "NSSVerifyClient require\n";
                } else {
                    $_ = "NSSVerifyClient none\n";
                }
            }
            print CONSOLECONF $_;
        }
        close(CONSOLECONF);
    }

    return 1;
}

sub migrateAdmpw {
    my $mig = shift;
    my $configdir = shift;
    if (-f "$mig->{oldsroot}/admin-serv/config/admpw") {
        if (system ("cp -p $mig->{oldsroot}/admin-serv/config/admpw $configdir/admpw")) {
            $mig->msg('error_copying_admpw', "$mig->{oldsroot}/admin-serv/config/admpw", $!);
            return 0;
        }
    }

    return 1;
}

sub migrateAdminServer {
    my $mig = shift;
    my @errs;

    if (!stopAdminServer()) {
        return 0;
    }

    my $configdir = $mig->{inf}->{admin}->{config_dir} ||
        $ENV{ADMSERV_CONF_DIR} ||
        $mig->{configdir} . "/admin-serv";

    my $securitydir = $mig->{inf}->{admin}->{security_dir} ||
        $configdir;

    my $logdir = $mig->{inf}->{admin}->{log_dir} ||
        $ENV{ADMSERV_LOG_DIR} ||
        "/var/log/dirsrv/admin-serv";

    my $rundir = $mig->{inf}->{admin}->{run_dir} ||
        $ENV{ADMSERV_PID_DIR} ||
        "/var/run/dirsrv";

    if (!getOldFileInfo($mig, $configdir)) {
        return 0;
    }

    if (!createASFilesAndDirs($mig, $configdir, $securitydir, $logdir, $rundir)) {
        return 0;
    }

    # change branding information
    $mig->{inf}->{admin}->{sie} =~ s/\bNetscape\b/389/g;
    $mig->{inf}->{admin}->{isie} =~ s/\bNetscape\b/389/g;

    # update ldapStart
    # if ldapStart is not an absolute path, we need to add
    # the directory server instance dir (ServerRoot) to it
    if ($mig->{inf}->{admin}->{ldapStart} &&
        !File::Spec->file_name_is_absolute($mig->{inf}->{admin}->{ldapStart})) {
        debug(1, "Need to make ldapStart an absolute path - ", $mig->{ServerRoot}, "/",
              $mig->{inf}->{admin}->{ldapStart}, "\n");
        $mig->{inf}->{admin}->{ldapStart} = $mig->{ServerRoot} . "/" . $mig->{inf}->{admin}->{ldapStart};
    }

    if (!updateAdmConf({ldapurl => $mig->{inf}->{General}->{ConfigDirectoryLdapURL},
                        userdn => $mig->{inf}->{General}->{ConfigDirectoryAdminID},
                        SuiteSpotUserID => $mig->{inf}->{General}->{SuiteSpotUserID},
                        SuiteSpotGroup => $mig->{inf}->{General}->{SuiteSpotGroup},
                        sysuser => $mig->{inf}->{admin}->{SysUser},
                        sysgroup => $mig->{inf}->{General}->{SuiteSpotGroup},
                        AdminDomain => $mig->{inf}->{General}->{AdminDomain},
                        sie => $mig->{inf}->{admin}->{sie},
                        isie => $mig->{inf}->{admin}->{isie},
                        ldapStart => $mig->{inf}->{admin}->{ldapStart}},
                       $configdir)) {
        return 0;
    }

    if (!migrateSecurityFiles($mig, $configdir)) {
        return 0;
    }

    my $conn = getConfigDSConn($mig->{inf}->{General}->{ConfigDirectoryLdapURL},
                               $mig->{inf}->{General}->{ConfigDirectoryAdminID},
                               $mig->{inf}->{General}->{ConfigDirectoryAdminPwd},
                               $configdir, \@errs);

    if (@errs) {
        $mig->msg($FATAL, @errs);
        return 0;
    }

    $mig->{inf}->{configdsconn} = $conn;
    $mig->{inf}->{slapd}->{updatedir} = "/usr/share/dirsrv/updates-admin";

    my @errs;
    if (@errs = updateDS($mig)) {
        $conn->close();
        $mig->msg(@errs);
        return 0;
    }

    my $admConf = getAdmConf($configdir);
    $mig->{inf}->{admin}->{sie} = $admConf->{sie};
    $mig->{inf}->{admin}->{isie} = $admConf->{isie};

    if (!migratePset($mig, $configdir)) {
        $conn->close();
        return 0;
    }

    if (!updateConsoleInfo($mig, $configdir)) {
        $conn->close();
        return 0;
    }

    $conn->close();

    if (!migrateAdmpw($mig, $configdir)) {
        return 0;
    }

    if (!updateConfFileSecInfo($mig, $configdir)) {
        return 0;
    }

    $mig->msg('updating_httpconf');
    if (!updateHttpConfFiles($mig->{inf}->{admin}->{ServerIpAddress},
                             $mig->{inf}->{admin}->{Port},
                             $configdir)) {
        $mig->msg($FATAL, 'error_updating_httpconf');
        return 0;
    }

    if (!setFileOwnerPerms($mig, $configdir)) {
        return 0;
    }

    # Update selinux policy
    updateSelinuxPolicy($mig, $configdir, $securitydir, $logdir, $rundir);

    if (!startAdminServer($mig, $configdir, $logdir, $rundir)) {
        return 0;
    }

    return 1;
}


# obligatory module true return
1;

# emacs settings
# Local Variables:
# mode:perl
# indent-tabs-mode: nil
# tab-width: 4
# End:
