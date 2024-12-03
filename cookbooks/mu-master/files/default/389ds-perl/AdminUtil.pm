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

package AdminUtil;
require Exporter;
@ISA       = qw(Exporter);
@EXPORT    = qw(getAdmConf getConfigDSConn createConfigDS createSubDS
                updateAdmConf updateAdmpw updateLocalConf importCACert
                getLocalConfigDS getPset registerDSWithConfigDS
                registerManyDSWithConfigDS createSubDSNoConn
                registerScatteredDSWithConfigDS getInfs getInfsVal
                unregisterDSWithConfigDS isConfigDS addConfigACIsToSubDS);
@EXPORT_OK = qw(getAdmConf getConfigDSConn createConfigDS createSubDS 
                updateAdmConf updateAdmpw updateLocalConf importCACert
                getLocalConfigDS getPset registerDSWithConfigDS
                registerManyDSWithConfigDS createSubDSNoConn
                registerScatteredDSWithConfigDS getInfs getInfsVal
                unregisterDSWithConfigDS isConfigDS addConfigACIsToSubDS);

# load perldap
use Mozilla::LDAP::Conn;
use Mozilla::LDAP::Utils qw(normalizeDN);
use Mozilla::LDAP::API qw(:constant ldap_url_parse ldap_explode_dn);
use Mozilla::LDAP::LDIF qw(enlist_values);

use DSUtil;
use Inf;
use FileConn;

use strict;

# get the adminutil client configuration (adm.conf)
# the file is in LDIF format
# just return as a hash ref for easy key/value access
# single valued attributes will have a single string value
# multi valued attributes will have an array ref value
sub getAdmConf {
    my $dir = shift || "/etc/dirsrv/admin-serv";
    my $ret = {};

    my $fname = "$dir/adm.conf";
    if (-f $fname) {
        open( ADMCONF, "$fname" ) || die "Can't open $fname: $!";
        my $in  = Mozilla::LDAP::LDIF->new(*ADMCONF, \&read_file_URL_or_name);
        my @records = $in->get(undef); # read to end of file
        close(ADMCONF);
        @records = enlist_values(@records);
        for (@records) { # there should only be 1 record
            my %h = @{$_}; # cast $_ to an array and use that to init hash
            $ret = \%h;
        }
        $ret->{configdir} = $dir;
    }

    return $ret;
}

# pset info is from the local.conf file, also in LDIF format
sub getPset {
    my $admConf = shift;
    my $configdir;
    if ($admConf) {
        if (ref($admConf)) {
            $configdir = $admConf->{configdir} || "/etc/dirsrv/admin-serv";
        } else {
            $configdir = $admConf || "/etc/dirsrv/admin-serv";
        }
    }
    my $ret = {};
    my $fname = "$configdir/local.conf";
    if (-f $fname) {
        open( LOCALCONF, "$fname" ) || die "Can't open $fname: $!";
        my $in = new Mozilla::LDAP::LDIF(*LOCALCONF);
        while (my $ent = readOneEntry $in) {
            foreach my $attr (keys %{$ent}) {
                my @vals = $ent->getValues($attr);
                if (@vals > 1) {
                    $ret->{$attr} = \@vals; # value is array ref
                } else {
                    $ret->{$attr} = $vals[0]; # value is single string
                }
            }
        }
        close LOCALCONF;
    }

    return $ret;
}

sub getAdmpw {
    my $admConf = shift;
    my $configdir;
    if ($admConf) {
        if (ref($admConf)) {
            $configdir = $admConf->{configdir} || "/etc/dirsrv/admin-serv";
        } else {
            $configdir = $admConf || "/etc/dirsrv/admin-serv";
        }
    }
    my $ret = {};
    my $fname = "$configdir/admpw";
    if (-f $fname) {
        open( ADMPW, "$fname" ) || die "Can't open $fname: $!";
        while (<ADMPW>) {
            chop;
            ($ret->{ServerAdminID}, $ret->{ServerAdminPwd}) = split /:/;
            last;
        }
        close ADMPW;
    }

    return $ret;
}

sub getCertDir {
    my $configdir = shift;
    # if configdir already ends in admin-serv, just use it
    if ($configdir =~ /admin-serv$/) {
        return $configdir;
    }
    # otherwise, assume configdir is the directory containing admin-serv
    return "$configdir/admin-serv";
}

sub isConfigDS {
    my $inst = shift;
    my $configdir = shift;
    my $admConf = getAdmConf ($configdir);
    my $ldapstart = $admConf->{ldapStart};
    my $expected = $inst . "/start-slapd";
    if ( "$ldapstart" eq "$expected" ) {
        return 1;
    } else {
        return 0;
    }
}

sub getConfigDSConn {
    my $url = shift;
    my $id = shift;
    my $pwd = shift;
    my $configdir = shift;
    my $errs = shift; # for output errs - an array ref
    my $certdir;
    my $errstr = "Success";
    my $conn;

    if (!$url or !$id) {
        my $admConf = getAdmConf($configdir);
        $url = $url || $admConf->{ldapurl};
        $id = $id || $admConf->{userdn};
    }

    my $h = ldap_url_parse($url);
    my $host = $h->{host};
    my $port = $h->{port};
    my $basedn = $h->{dn};

    # If PerLDAP was build using OpenLDAP, we must check the URL scheme
    # to see if we're using LDAPS.  If MozLDAP is being used, we need
    # to check for the secure option.
    if ($h->{scheme}) {
        if ($h->{scheme} eq "ldaps") {
            $certdir = getCertDir($configdir);
        }
    } elsif ($h->{options} & LDAP_URL_OPT_SECURE) {
        $certdir = getCertDir($configdir);
    }

    if ($id =~ /=/){
        #
        # We have a bind DN so try it first, as anonymous access could be
        # disabled on the config DS.
        #
        debug(3, "Attempting connection to " . $h->{host} . ":" . $h->{port} .
              " bind DN ($id) certdir $certdir configdir $configdir\n");
        $conn = new Mozilla::LDAP::Conn($h->{host}, $h->{port}, $id, $pwd, $certdir);
        if ($conn) {
            $errstr = $conn->getErrorString();
        }
        if (!$conn or ($errstr ne "Success")) {
            if ($conn) {
                $conn->close();
                $conn = 0;
            }
            if ($certdir) {
                push @{$errs}, 'configds_open_error_ssl', $url,
                     ($errstr eq "Success") ? 'unknown error' : $errstr,
                     $h->{host}, $h->{port}, $h->{host}, $h->{host}, $certdir, $h->{host}, $h->{port};
            } else {
                push @{$errs}, 'configds_open_error', $url,
                     ($errstr eq "Success") ? 'unknown error' : $errstr,
                     $h->{host}, $h->{port}, $h->{host}, $h->{host}, $h->{host}, $h->{port};
            }
            return $conn;
        }
    } else {
        #
        # We must attempt an anonymous bind to find the entry
        #
        debug(3, "Attempting connection to " . $h->{host} . ":" . $h->{port} .
              " bind DN(anonymous) certdir $certdir configdir $configdir\n");
        $conn = new Mozilla::LDAP::Conn($h->{host}, $h->{port}, "", "", $certdir);
        if ($conn) {
            $errstr = $conn->getErrorString();
        }
        if (!$conn or ($errstr ne "Success")) {
            if ($conn) {
                $conn->close();
                $conn = 0;
            }
            if ($certdir) {
                push @{$errs}, 'configds_open_error_ssl', $url,
                     ($errstr eq "Success") ? 'unknown error' : $errstr,
                     $h->{host}, $h->{port}, $h->{host}, $h->{host}, $certdir, $h->{host}, $h->{port};
            } else {
                push @{$errs}, 'configds_open_error', $url,
                     ($errstr eq "Success") ? 'unknown error' : $errstr,
                     $h->{host}, $h->{port}, $h->{host}, $h->{host}, $h->{host}, $h->{port};
            }
            return $conn;
        }

        # Search for the entry - we assume it starts with uid
        my $ent = $conn->search($h->{dn}, "sub", "(uid=$id)", 1, 'dn');
        $errstr = $conn->getErrorString();
        if (!$ent or ($errstr ne "Success")) {
            $conn->close();
            $conn = 0;
            push @{$errs}, 'configds_finddn_error', $id, $url, (($errstr eq "Success") ? 'unknown error' : $errstr);
            return $conn;
        }
        # Now bind as the entry
        $id = $ent->getDN();
        if (!$conn->simpleAuth($id, $pwd)) {
            $errstr = $conn->getErrorString();
            $conn->close();
            $conn = 0;
            if ($errstr =~ /constraint/i) {
                push @{$errs}, 'configds_bindretry_error', $id, $url;
            } else {
                push @{$errs}, 'configds_bind_error', $id, $url, (($errstr eq "Success") ? 'unknown error' : $errstr);
            }
            return $conn;
        }
    }
    # store the binddn and password for later use
    $conn->setDefaultRebindProc($id, $pwd, LDAP_AUTH_SIMPLE);
    $conn->{adminbinddn} = $id;

    return $conn;
}

sub verifyAdminDomain {
    my $conn = shift;
    my $url = shift;
    my $domain = shift;

    my $h = ldap_url_parse($url);
    my $dn = "ou=$domain, $h->{dn}";
    my $ent = $conn->search($dn, "base", "(objectclass=*)", 1, 'dn');
    my $errstr = $conn->getErrorString();
    if (!$ent or ($errstr ne "Success")) {
        return ('configds_no_admindomain', $domain, $h->{dn}, (($errstr eq "Success") ? 'unknown error' : $errstr));
    }
    return ();
}

# Take the slapd server instance specified in the slapd section of the given inf
# and make it into a configuration directory server
sub createConfigDS {
    my $inf = shift;
    my $errs = shift;

    # open a connection to the directory server
    my $conn = new Mozilla::LDAP::Conn($inf->{General}->{FullMachineName},
                                       $inf->{slapd}->{ServerPort},
                                       $inf->{slapd}->{RootDN},
                                       $inf->{slapd}->{RootDNPwd},
                                       $inf->{General}->{certdir});
    my $errstr;
    if ($conn) {
        $errstr = $conn->getErrorString();
    }
    if (!$conn or ($errstr ne "Success")) {
        @{$errs} = ('error_connection_failed', $inf->{General}->{FullMachineName},
                    $inf->{slapd}->{ServerPort}, $inf->{slapd}->{RootDN},
                    ($conn ? $errstr : "unknown"));
        if ($conn) {
            $conn->close();
        }
        return 0;
    }

    # add the NetscapeRoot suffix
    @{$errs} = addSuffix($conn, "o=NetscapeRoot", "NetscapeRoot");
    if (@{$errs}) {
        $conn->close();
        return 0;
    }

    # add the o=NetscapeRoot tree using the mapper and ldif templates
    my @ldiffiles = ('/usr/share/dirsrv/data/01nsroot.ldif.tmpl',
                     '/usr/share/dirsrv/data/02globalpreferences.ldif.tmpl',
                     '/usr/share/dirsrv/data/12dsconfig.mod.tmpl',
                     '/usr/share/dirsrv/data/13dsschema.mod.tmpl',
                     '/usr/share/dirsrv/data/14dsmonitor.mod.tmpl',
                     '/usr/share/dirsrv/data/16dssuffixadmin.mod.tmpl'
                     );
    my @infs = getInfs("slapd", "admin", "setup");
    my $mapper = new Inf("/usr/share/dirsrv/inf/configdsroot.map");

    $mapper = process_maptbl($mapper, $errs, $inf, @infs);
    if (!$mapper or @{$errs}) {
        $conn->close();
        if (!@{$errs}) {
            @{$errs} = ('error_creating_configds_maptbl');
        }
        return 0;
    }

    getMappedEntries($mapper, \@ldiffiles, $errs, \&check_and_add_entry,
                     [$conn]);

    $conn->close();
    return @{$errs} ? 0 : 1;
}

sub internalCreateSubDS {
    my $conn = shift;
    my $inf = shift;
    my $errs = shift;
    my $force_pta = shift;
    my @additionalLdifFiles = @_;

    # add the o=NetscapeRoot tree using the mapper and ldif templates
    my @ldiffiles = ('/usr/share/dirsrv/data/12dsconfig.mod.tmpl',
                     '/usr/share/dirsrv/data/13dsschema.mod.tmpl',
                     '/usr/share/dirsrv/data/14dsmonitor.mod.tmpl'
                     );
    push @ldiffiles, @additionalLdifFiles;

    # If PTA is not enabled yet, we need to enable and configure it
    my $ent = $conn->search("cn=Pass Through Authentication,cn=plugins,cn=config", "base", "(objectclass=*)", 0, 'nsslapd-pluginenabled');
    my $errstr = $conn->getErrorString();
    if (!$ent or ($errstr ne "Success")) {
        $conn->close();
        @{$errs} = ('error_finding_pta', (($errstr eq "Success") ? 'unknown error' : $errstr));
        return 0;
    }

    if (($ent->hasValue("nsslapd-pluginenabled", "off", 1)) || $force_pta == 1) {
        push @ldiffiles, '/usr/share/dirsrv/data/15dspta.mod.tmpl';
    }
    
    my @infs = getInfs("slapd", "admin", "setup");
    my $mapper = new Inf("/usr/share/dirsrv/inf/dirserver.map");

    $mapper = process_maptbl($mapper, $errs, $inf, @infs);
    if (!$mapper or @{$errs}) {
        $conn->close();
        if (!@{$errs}) {
            @{$errs} = ('error_creating_configds_maptbl');
        }
        return 0;
    }

    getMappedEntries($mapper, \@ldiffiles, $errs, \&check_and_add_entry,
                     [$conn]);

    $conn->close();
    return @{$errs} ? 0 : 1;
}

# Take the slapd server instance specified in the slapd section of the given inf
# and make it into a subordinative directory server
# (no o=netscaperoot, with PTA setup)
sub createSubDS {
    my $inf = shift;
    my $errs = shift;
    my $force_pta = shift;

    # open a connection to the directory server
    my $conn = new Mozilla::LDAP::Conn($inf->{General}->{FullMachineName},
                                       $inf->{slapd}->{ServerPort},
                                       $inf->{slapd}->{RootDN},
                                       $inf->{slapd}->{RootDNPwd},
                                       $inf->{General}->{certdir});
    if (!$conn) {
        @{$errs} = ('error_connection_failed', $inf->{General}->{FullMachineName},
                    $inf->{slapd}->{ServerPort}, $inf->{slapd}->{RootDN},
                    "unknown");
        return 0;
    }

    return internalCreateSubDS($conn, $inf, $errs, $force_pta, '/usr/share/dirsrv/data/16dssuffixadmin.mod.tmpl');
}

# same as createSubDS but works directly on the dse.ldif file itself
# this is suitable for use when creating a new DS instance on the local
# machine,
sub createSubDSNoConn {
    my $inf = shift;
    my $errs = shift;
    # $ENV{DS_CONFIG_DIR} is set in ds instance creation
    my $dsconfdir = $ENV{DS_CONFIG_DIR} ||
        "/etc/dirsrv/slapd-" . $inf->{slapd}->{ServerIdentifier};

    my $dseldif = "$dsconfdir/dse.ldif";
    my $conn = new FileConn($dseldif);
    if (!$conn) {
        @{$errs} = ('error_opening_dseldif', $dseldif, $!);
        return 0;
    }

    return internalCreateSubDS($conn, $inf, $errs, 0);
}

sub addConfigACIsToSubDS {
    my $inf = shift;
    my $errs = shift;

    # open a connection to the directory server
    my $conn = new Mozilla::LDAP::Conn($inf->{General}->{FullMachineName},
                                       $inf->{slapd}->{ServerPort},
                                       $inf->{slapd}->{RootDN},
                                       $inf->{slapd}->{RootDNPwd},
                                       $inf->{General}->{certdir});
    if (!$conn) {
        @{$errs} = ('error_connection_failed', $inf->{General}->{FullMachineName},
                    $inf->{slapd}->{ServerPort}, $inf->{slapd}->{RootDN},
                    "unknown");
        return 0;
    }

    my @ldiffiles = ('/usr/share/dirsrv/data/16dssuffixadmin.mod.tmpl');
    my @infs = getInfs("slapd", "admin", "setup");
    my $mapper = new Inf("/usr/share/dirsrv/inf/dssuffixadmin.map");

    $mapper = process_maptbl($mapper, $errs, $inf, @infs);
    if (!$mapper or @{$errs}) {
        $conn->close();
        if (!@{$errs}) {
            @{$errs} = ('error_creating_configds_maptbl');
        }
        return 0;
    }

    getMappedEntries($mapper, \@ldiffiles, $errs, \&check_and_add_entry,
                     [$conn]);

    $conn->close();
    return @{$errs} ? 0 : 1;
}

sub updateAdmConf {
    my $params = shift; # hashref
    my $configdir = shift || "/etc/dirsrv/admin-serv";
    my $admConf = getAdmConf($configdir);
    my $isnew = 0;
    if (!$admConf || !%{$admConf}) {
        $isnew = 1; # create it
    }

    # update values in admConf with the passed in params
    while (my ($key,$val) = each %{$params}) {
        $admConf->{$key} = $val;
    }

    # write it out
    my $filename = "$configdir/adm.conf";
    delete $admConf->{configdir}; # don't write this
    open(ADMCONF, "> $filename") || die "Can't write $filename: $!";
    while (my ($key,$val) = each %{$admConf}) {
        next if (!defined($key) or !defined($val));
        if (ref($val)) {
            for my $vv (@{$val}) {
                print ADMCONF "$key: $vv\n";
            }
        } else {
            print ADMCONF "$key: $val\n";
        }
    }
    close(ADMCONF);

    if ($isnew) {
        my $uid = getpwnam $admConf->{sysuser};
        chmod 0600, "$filename";
        chown $uid, -1, "$filename";
    }

    return 1;
}

sub updateAdmpw {
    my $userid = shift;
    my $pwd = shift;
    my $configdir = shift || "/etc/dirsrv/admin-serv";
    my $filename = "$configdir/admpw";
    my $isnew = 0;
    if (! -f $filename) {
        $isnew = 1;
    }

    $pwd = getHashedPassword($pwd, "SHA");

    open(ADMPW, ">$filename") or die "Error: can't write file $filename: $!";
    print ADMPW "$userid:$pwd\n";
    close(ADMPW);

    if ($isnew) {
        my $admConf = getAdmConf($configdir);
        my $uid = getpwnam $admConf->{sysuser};
        chmod 0600, "$filename";
        chown $uid, -1, "$filename";
    }

    return 1;
}

# this is the prefix used for attribute names in the pset file
sub getAttrNamePrefix {
    my $dn = shift;
    my $rootdn = shift; # the sie DN

    my @dnList = ldap_explode_dn($dn, 1);
    my @rootdnList = ldap_explode_dn($rootdn, 1);

    my $attrLen = scalar(@dnList) - scalar(@rootdnList);
    my $attrName = "";
    while ($attrLen > 0) {
        if ($attrLen == 1) {
            $attrName .= $dnList[0];
        } else {
            $attrName .= $dnList[$attrLen-1] . ".";
        }
        $attrLen--;
    }

    return $attrName;
}

# these are attributes not written to the pset
my %nopsetattrs = (
    cn => 'cn',
    aci => 'aci'
);

# This is only used during setup.
# When the admin server is running, changes
# occur online, and the file contains a cache
# of those changes
# but during setup, we need to create the
# local.conf as a bootstrap for the server
sub updateLocalConf {
    my $entry = shift;
    my $siedn = shift;
    my $localfh = shift;

    # convert entry to pset format
    my $prefix = getAttrNamePrefix($entry->getDN(), $siedn);

    # write values to file
    foreach my $attr (keys %{$entry}) {
        next if $nopsetattrs{lc($attr)};
        my $attrName;
        if ($prefix) {
            $attrName = $prefix . "." . $attr;
        } else {
            $attrName = $attr;
        }
        foreach my $val ($entry->getValues($attr)) {
            debug(3, "updateLocalConf: writing $attrName: $val\n");
            print $localfh "$attrName: $val\n";
        }
    }

    return 1;
}

sub importCACert {
    my $securitydir = shift;
    my $cacert = shift; # may be a file or the actual cert in ascii/pem format
    my @errs = (); # return

    if (! -d $securitydir) {
        @errs = ('securitydir_not_exist', $securitydir);
        return @errs;
    }

    if (! -w $securitydir) {
        @errs = ('securitydir_not_writable', $securitydir);
        return @errs;
    }

    # see if "CA certificate" already exists
    my $output = `certutil -L -d \"$securitydir\" 2>&1`;
    if ($output =~ /CA certificate/) {
        @errs = ('cacert_already_exists', $securitydir);
        return @errs;
    }

    if ($cacert =~ /^-----BEGIN CERTIFICATE-----/) {
        $! = 0;
        $? = 0; # clear error indicators
        if (!open(CERTUTIL, "|certutil -A -d \"$securitydir\" -a -t CT,, -n \"CA certificate\"")) {
            @errs = ("error_running_certutil", $!);
            return @errs;
        }
        print CERTUTIL $cacert, "\n";
        close(CERTUTIL);
        if ($?) {
            @errs = ('error_return_certutil', $?, $!);
            return @errs;
        }
    } elsif (! -f $cacert) {
        @errs = ('cacertfile_not_found', $cacert);
        return @errs;
    } else {
        $! = 0;
        $? = 0; # clear error indicators
        $output = `certutil -A -d \"$securitydir\" -a -t CT,, -n \"CA certificate\" -i \"$cacert\" 2>&1`;
        if ($?) {
            @errs = ('error_return2_certutil', $?, $!, $output);
            return @errs;
        }
    }

    return @errs;
}

# if the config ds is local to this machine, return
# the instance name (e.g. "localhost" for slapd-localhost)
# if not, return null
sub getLocalConfigDS {
    my $configdir = shift;
    my $admConf = getAdmConf($configdir);
    my $ldapStart = $admConf->{ldapStart};
    my $inst;
    if (!$ldapStart) {
        return $inst; # empty
    }

    if ($ldapStart =~ /slapd-(.+?)\//) {
        $inst = $1;
    } else {
        # The instance name might not prefixed with "slapd-"
        my @parts = split / /, $ldapStart;
        if ($#parts > 0){
            $inst = $parts[1];
        }
    }

    return $inst;
}

# most admin server CGIs only use PASSWORD and USERDN
sub getAuthCredentials {
    if ($AdminUtil::USER) {
        return ($AdminUtil::USER, $AdminUtil::PASSWORD,
                $AdminUtil::AUTHORIZATION, $AdminUtil::USERDN,
                $AdminUtil::SIEPWD);
    }

    if (!defined($ENV{PASSWORD_PIPE})) {
        return ();
    }

    my $fh;
    if (fileno(STDIN) == $ENV{PASSWORD_PIPE}) {
        $fh = \*STDIN;
    } else {
        open(INPUT, "<&=$ENV{PASSWORD_PIPE}") or
            die "Error: could not open PASSWORD_PIPE $ENV{PASSWORD_PIPE}: $!";
        $fh = \*INPUT;
    }
    while (<$fh>) {
        if (/^User: (.*)$/) {
            $AdminUtil::USER = $1;
        }
        if (/^Password: (.*)$/) {
            $AdminUtil::PASSWORD = $1;
        }
        if (/^Authorization: (.*)$/) {
            $AdminUtil::AUTHORIZATION = $1;
        }
        if (/^UserDN: (.*)$/) {
            $AdminUtil::USERDN = $1;
        }
        if (/^SIEPWD: (.*)$/) {
            $AdminUtil::SIEPWD = $1;
        }
    }
    if (fileno(STDIN) != $ENV{PASSWORD_PIPE}) {
        close $fh;
    }

    return ($AdminUtil::USER, $AdminUtil::PASSWORD,
            $AdminUtil::AUTHORIZATION, $AdminUtil::USERDN,
            $AdminUtil::SIEPWD);
}

# this takes a list of DS instances and registers all of them
# with the config DS
sub registerManyDSWithConfigDS {
    my $inf = shift;
    my $errs = shift;
    my $configdir = shift;
    my @instances = @_;

    if (!@instances) {
        return 1; # no instances to register - just return ok
    }

    # open a connection to the configuration directory server
    my $conn = getConfigDSConn($inf->{General}->{ConfigDirectoryLdapURL},
                               $inf->{General}->{ConfigDirectoryAdminID},
                               $inf->{General}->{ConfigDirectoryAdminPwd},
                               "$configdir/admin-serv", $errs);

    if (!$conn or @{$errs}) {
        return 0;
    }

    my $admConf = getAdmConf("$configdir/admin-serv");

    for my $inst (@instances) {
        my $instinf = createInfFromConfig("$configdir/$inst", $inst);
        if ($instinf->{filename}) {
            unlink($instinf->{filename});
        }
        $instinf->{General}->{ConfigDirectoryLdapURL} = 
            $inf->{General}->{ConfigDirectoryLdapURL};
        $instinf->{General}->{ConfigDirectoryAdminID} = 
            $inf->{General}->{ConfigDirectoryAdminID};
        $instinf->{General}->{AdminDomain} = $inf->{General}->{AdminDomain};
        $instinf->{admin}->{ServerAdminID} = $inf->{admin}->{ServerAdminID};
        if (!registerDSWithConfigDS($inst, $errs, $instinf,
                                    $conn, $admConf, $configdir)) {
            return 0;
        }
    }

    $conn->close();

    return 1
}
sub registerScatteredDSWithConfigDS {
    my $inf = shift;
    my $errs = shift;
    my $instances_ref = shift;
    my @configdirs = keys %{$instances_ref};
    my $configdir = $configdirs[0]; # use the first configdir for admin-serv

    if ( ! $instances_ref ) {
        return 1; # no instances to register - just return ok
    }

    # open a connection to the configuration directory server
    my $conn = getConfigDSConn($inf->{General}->{ConfigDirectoryLdapURL},
                               $inf->{General}->{ConfigDirectoryAdminID},
                               $inf->{General}->{ConfigDirectoryAdminPwd},
                               "$configdir/admin-serv", $errs);

    if (!$conn or @{$errs}) {
        return 0;
    }

    my $admConf = getAdmConf("$configdir/admin-serv");

    for $configdir ( @configdirs ) {
        foreach my $dsinst ( @{$instances_ref->{$configdir}} ) {
            my $instinf = createInfFromConfig("$configdir/$dsinst", $dsinst);
            if ($instinf->{filename}) {
                unlink($instinf->{filename});
            }
            $instinf->{General}->{ConfigDirectoryLdapURL} = 
                $inf->{General}->{ConfigDirectoryLdapURL};
            $instinf->{General}->{AdminDomain} = $inf->{General}->{AdminDomain};
            $instinf->{General}->{ConfigDirectoryAdminID} = $inf->{General}->{ConfigDirectoryAdminID};
            $instinf->{General}->{ServerAdminID} = $inf->{General}->{ServerAdminID};
            if (!registerDSWithConfigDS($dsinst, $errs, $instinf,
                                    $conn, $admConf, $configdir)) {
                return 0;
            }
        }
    }

    $conn->close();

    return 1
}

sub registerDSWithConfigDS {
    my $servid = shift;
    my $errs = shift;
    my $inf = shift;
    my $conn = shift;
    my $admConf = shift;
    my $configdir = shift || "/etc/dirsrv";

    my $rc = registerDSWithConfigDSExt(1, $servid, $errs, $inf, 
                                       $conn, $admConf, $configdir);
    return $rc;
}

sub unregisterDSWithConfigDS {
    my $servid = shift;
    my $errs = shift;
    my $inf = shift;
    my $conn = shift;
    my $admConf = shift;
    my $configdir = shift || "/etc/dirsrv";
    my $rc = registerDSWithConfigDSExt(0, $servid, $errs, $inf, 
                                       $conn, $admConf, $configdir);
    return $rc;
}

sub registerDSWithConfigDSExt {
    my $isRegister = shift;
    my $servid = shift;
    my $errs = shift;
    my $inf = shift;
    my $conn = shift;
    my $admConf = shift;
    my $configdir = shift || "/etc/dirsrv";
    my $inst;
    my $needclose;

    if ($servid =~ /^slapd-/) {
        $inst = $servid;
    } else {
        $inst = "slapd-$servid";
    }

    my ($dummy1, $pwd, $dummy2, $userdn) = getAuthCredentials();

    if (!$inf->{General}->{AdminDomain}) {
        if (!$admConf) {
            $admConf = getAdmConf("$configdir/admin-serv");
        }
        $inf->{General}->{AdminDomain} = $admConf->{AdminDomain};
    }

    # open a connection to the configuration directory server
    if (!$conn) {
        if (!$userdn) {
            $userdn = $inf->{General}->{ConfigDirectoryAdminID};
        }
        if (!$pwd) {
            $pwd = $inf->{General}->{ConfigDirectoryAdminPwd};
        }
            
        $conn = getConfigDSConn($inf->{General}->{ConfigDirectoryLdapURL},
                                $userdn, $pwd,
                                "$configdir/admin-serv", $errs);
        $needclose = 1;
    }

    if (!$conn or @{$errs}) {
        return 0;
    }

    # need to get the admin uid
    if (!$inf->{admin}->{ServerAdminID}) {
        my @rdns = ldap_explode_dn($inf->{General}->{ConfigDirectoryAdminID}, 1);
        if (@rdns and $rdns[0]) {
            $inf->{admin}->{ServerAdminID} = $rdns[0];
        } else { # a userid not a dn
            $inf->{admin}->{ServerAdminID} = $inf->{General}->{ConfigDirectoryAdminID};
        }
    }

    my $instinf;
    # setup will usually supply everything, but ds_create will not
    if ($isRegister && !$inf->{slapd}->{RootDNPwd}) {
        $instinf = createInfFromConfig("$configdir/$inst", $inst, $errs);
        if (!$instinf or @{$errs}) {
            if ($needclose) {
                $conn->close();
            }
            return 0;
        }
    }

    my @ldiffiles = ();
    if ($isRegister)
    {
        # add the Admin Server configuration entries
        @ldiffiles = ("/usr/share/dirsrv/data/10dsdata.ldif.tmpl",
                      "/usr/share/dirsrv/data/11dstasks.ldif.tmpl"
                     );
    }
    else
    {
        # remove the Admin Server configuration entries
        @ldiffiles = ("/usr/share/dirsrv/data/10rm_dsdata.ldif.tmpl");
    }
    my @infs = getInfs("slapd", "setup", "admin");
    my $mapper = new Inf("/usr/share/dirsrv/inf/dirserver.map");

    $mapper = process_maptbl($mapper, $errs, $inf, $instinf, @infs);
    if (!$mapper or @{$errs}) {
        if ($needclose) {
            $conn->close();
        }
        return 0;
    }

    my $context = [$conn];
    getMappedEntries($mapper, \@ldiffiles, $errs, \&check_and_add_entry, $context);

    if ($needclose) {
        $conn->close();
    }

    return @{$errs} ? 0 : 1;
}

# return Inf objects for the given names - the names correspond
# to .inf file names in the infdir - the list will be ordered
# so that brand specific names come before generic names -
# it is assumed in .inf processing that if a value is found
# in an earlier Inf later Infs will be ignored
sub getInfs {
    my @names = @_;
    my @ary;
    my @infs = glob("/usr/share/dirsrv/inf/*.inf");
    for my $name (@names) {
        for my $inffile (@infs) {
            if ($inffile =~ m,^/usr/share/dirsrv/inf/.+-$name\.inf$,) {
                # brand specific
                debug(2, "Found brand specific inf file", $inffile, "\n");
                push @ary, new Inf($inffile);
            }
        }
    }
    # added all brand specific inf files, if any - now add generic inf files
    for my $name (@names) {
        push @ary, new Inf("/usr/share/dirsrv/inf/$name.inf");
    }

    return @ary;
}

# get a value from a collection of Inf objects
# given a section and a parameter, will return
# the value from the first Inf that has the
# section and value
sub getInfsVal {
    my ($sec, $parm, @infs) = @_;
    for my $inf (@infs) {
        if ($inf and exists($inf->{$sec}) and defined($inf->{$sec}) and
            exists($inf->{$sec}->{$parm}) and defined($inf->{$sec}->{$parm})) {
            return $inf->{$sec}->{$parm};
        }
    }
    return undef;
}

1;

# emacs settings
# Local Variables:
# mode:perl
# indent-tabs-mode: nil
# tab-width: 4
# End:
