# BEGIN COPYRIGHT BLOCK
# Copyright (C) 2013 Red Hat, Inc.
# All rights reserved.
#
# License: GPL (version 3 or any later version).
# See LICENSE for details. 
# END COPYRIGHT BLOCK
#

###########################
#
# This perl module provides a way to create a new instance of
# directory server.
#
##########################

package DSCreate;
use DSUtil;
use Inf;
use FileConn;
use Config;

use Sys::Hostname;
# tempfiles
use File::Temp qw(tempfile tempdir);
use File::Path;
use File::Copy;
use File::Basename qw(basename dirname);
use POSIX qw(:errno_h);

# load perldap
use Mozilla::LDAP::Conn;
use Mozilla::LDAP::Utils qw(normalizeDN);
use Mozilla::LDAP::API qw(ldap_explode_dn);
use Mozilla::LDAP::LDIF;

use POSIX ":sys_wait_h";

use Exporter;
@ISA       = qw(Exporter);
@EXPORT    = qw(createDSInstance removeDSInstance setDefaults createInstanceScripts
                makeOtherConfigFiles installSchema updateSelinuxPolicy updateTmpfilesDotD
                get_initconfigdir updateSystemD makeDSDirs);
@EXPORT_OK = qw(createDSInstance removeDSInstance setDefaults createInstanceScripts
                makeOtherConfigFiles installSchema updateSelinuxPolicy updateTmpfilesDotD
                get_initconfigdir updateSystemD makeDSDirs);

use strict;

use SetupLog;

sub get_initconfigdir {
    my $prefix = shift;
    
    # determine initconfig_dir
    if (getLogin eq 'root') {
        return "$prefix/etc/sysconfig";
    } else {
        return "$ENV{HOME}/.dirsrv";
    }
}

sub checkPort {
    my $inf = shift;

    # allow port 0 if ldapi is used
    if ("1") {
        if ($inf->{slapd}->{ldapifilepath} &&
            ($inf->{slapd}->{ServerPort} == 0)) {
            return ();
        }
    }

    if ($inf->{slapd}->{ServerPort} !~ /^\d+$/) {
        return ('error_port_invalid', $inf->{slapd}->{ServerPort});
    }
    if (!portAvailable($inf->{slapd}->{ServerPort})) {
        return ('error_port_available', $inf->{slapd}->{ServerPort}, $!);
    }

    return ();
}

# checks the parameters in $inf to make sure the supplied values
# are valid
# returns null if successful, or an error string for use with getText()
sub sanityCheckParams {
    my $inf = shift;
    my @errs = ();

    # if we don't need to start the server right away, we can skip the
    # port number checks
    if (!defined($inf->{slapd}->{start_server}) or
        ($inf->{slapd}->{start_server} == 1)) {

        if (@errs = checkPort($inf)) {
            return @errs;
        }
    }

    if($inf->{slapd}->{ServerIdentifier} eq "admin"){
        return ('error_reserved_serverid' ,"admin");
    } elsif (!isValidServerID($inf->{slapd}->{ServerIdentifier})) {
        return ('error_invalid_serverid', $inf->{slapd}->{ServerIdentifier});
    } elsif (-d $inf->{slapd}->{config_dir}) {
        return ('error_server_already_exists', $inf->{slapd}->{config_dir});
    }

    if (@errs = isValidUser($inf->{General}->{SuiteSpotUserID})) {
        return @errs;
    }

    if (@errs = isValidGroup($inf->{General}->{SuiteSpotGroup})) {
        return @errs;
    }

    if (!isValidDN($inf->{slapd}->{Suffix})) {
        return ('dialog_dssuffix_error', $inf->{slapd}->{Suffix});
    }

    if (!isValidDN($inf->{slapd}->{RootDN})) {
        return ('dialog_dsrootdn_error', $inf->{slapd}->{RootDN});
    }

    if ($inf->{slapd}->{RootDNPwd} =~ /^\{\w+\}.+/) {
        debug(1, "The root password is already hashed - no checking will be performed\n");
    } elsif (length($inf->{slapd}->{RootDNPwd}) < 8) {
        debug(0, "WARNING: The root password is less than 8 characters long.  You should choose a longer one.\n");
    }

    $inf->{General}->{StrictHostCheck} = lc $inf->{General}->{StrictHostCheck};

    if ("true" ne $inf->{General}->{StrictHostCheck} && "false" ne $inf->{General}->{StrictHostCheck}) {
        debug(1, "StrictHostCheck is not a valid boolean");
        return ('error_invalid_boolean', $inf->{General}->{StrictHostCheck});
    }

    if ($inf->{General}->{StrictHostCheck} eq "true" ) {
        if (@errs = checkHostname($inf->{General}->{FullMachineName}, 0)) {
            debug(1, @errs);
            return @errs;
        }
    }

    # We need to make sure this value is lowercase
    $inf->{slapd}->{InstScriptsEnabled} = lc $inf->{slapd}->{InstScriptsEnabled};

    if ("true" ne $inf->{slapd}->{InstScriptsEnabled} && "false" ne $inf->{slapd}->{InstScriptsEnabled}) {
        debug(1, "InstScriptsEnabled is not a valid boolean");
        return ('error_invalid_boolean', $inf->{slapd}->{InstScriptsEnabled});
    }


    return ();
}

sub getMode {
    my $inf = shift;
    my $mode = shift;
    my $rest = shift;
    if (!$rest) {
        $rest = "0";
    }
    if (defined($inf->{General}->{SuiteSpotGroup})) {
        $mode = "0" . $mode . $mode . $rest;
    } else {
        $mode = "0" . $mode . $rest . $rest;
    }

    return oct($mode);
}

# This is used to change the ownership and permissions of files and directories
# The mode is just a single digit octal number (e.g. 4 6 7)
# If there is a group, the ownership and permissions will allow group access
# otherwise, only the owner will be allowed access
sub changeOwnerMode {
    my $inf = shift;
    my $mode = shift;
    my $it = shift;
    my $gidonly = shift;
    my $othermode = shift;

    my $uid = getpwnam $inf->{General}->{SuiteSpotUserID};
    my $gid = -1; # default to leave it alone
    my $mode_string = "";

    if (defined($inf->{General}->{SuiteSpotGroup})) {
        $gid = getgrnam $inf->{General}->{SuiteSpotGroup};
    }

    $mode = getMode($inf, $mode, $othermode);

    $! = 0; # clear errno
    chmod $mode, $it;
    if ($!) {
        return ('error_chmoding_file', $it, $!);
    }

    $mode_string = sprintf "%lo", $mode;
    debug(1, "changeOwnerMode: changed mode of $it to $mode_string\n");

    $! = 0; # clear errno
    if ( $gidonly ) {
        chown -1, $gid, $it;
    } else {
        chown $uid, $gid, $it;
    }
    if ($!) {
        return ('error_chowning_file', $it, $inf->{General}->{SuiteSpotUserID}, $!);
    }

    if ( $gidonly ) {
        debug(1, "changeOwnerMode: changed group ownership of $it to group $gid\n");
    } else {
        debug(1, "changeOwnerMode: changed ownership of $it to user $uid group $gid\n");
    }

    return ();
}

sub makeDSDirs {
    my $inf = shift;
    my $verbose = ($DSUtil::debuglevel > 0);
    my $mode = getMode($inf, 7);
    my @errs;

    my @dsdirs = qw(config_dir schema_dir log_dir lock_dir run_dir tmp_dir cert_dir db_dir ldif_dir bak_dir);
    if ($inf->{slapd}->{InstScriptsEnabled} eq "true") {
        @dsdirs = qw(inst_dir config_dir schema_dir log_dir lock_dir run_dir tmp_dir cert_dir db_dir ldif_dir bak_dir);
    }

    # These paths are owned by the SuiteSpotGroup
    # This allows the admin server to run as a different,
    # more privileged user than the directory server, but
    # still allows the admin server to manage directory
    # server files/dirs without being root
    for my $kw (@dsdirs) {
        my $dir = $inf->{slapd}->{$kw};
        @errs = makePaths($dir, $mode, $inf->{General}->{SuiteSpotUserID},
                          $inf->{General}->{SuiteSpotGroup});
        if (@errs) {
            return @errs;
        }
    }
    # run_dir is a special case because it is usually shared among
    # all instances and the admin server
    # all instances must be able to write to it
    # if the SuiteSpotUserID is root or 0, we can just skip
    # this because root will have access to it - we really
    # shouldn't be using root anyway, primarily just for
    # legacy migration support
    # if there are two different user IDs that need access
    # to this directory, then SuiteSpotGroup must be defined,
    # and both users must be members of the SuiteSpotGroup
    if (($inf->{General}->{SuiteSpotUserID} eq 'root') ||
        (defined($inf->{General}->{SuiteSpotUserID}) &&
         ($inf->{General}->{SuiteSpotUserID} =~ /^0$/))) {
        # skip
        debug(3, "Root user " . $inf->{General}->{SuiteSpotUserID} . " already has access to $inf->{slapd}->{run_dir} - skipping\n");
    } else {
        my $dir = $inf->{slapd}->{run_dir};
        # rwx by user only, or by user & group if a group is defined.  Also only change the group ownership.
        @errs = changeOwnerMode($inf, 7, $dir, 1);
        debug(3, "\t" . `/bin/ls -ld $dir`);
    }
    # set the group of the parent dir of config_dir and inst_dir
    if (defined($inf->{General}->{SuiteSpotGroup})) {
        for my $kw (qw(inst_dir config_dir)) {
            my $dir = $inf->{slapd}->{$kw};
            my $parent = dirname($dir);
            # changeOwnerMode(inf, mode, file, gidonly, othermode);
            @errs = changeOwnerMode($inf, 7, $parent, 1, 5);
            if (@errs) {
                return @errs;
            }
        }
    }

    return @errs;
}

sub createInstanceScripts {
    my $inf = shift;
    my $skip = shift;
    my $perlexec = "/usr/bin/perl" || "/usr/bin/env perl";
    my $myperl = "!$perlexec";
    my $mydevnull = (-c "/dev/null" ? " /dev/null " : " NUL ");

    # If we have InstScriptsEnabled, we likely have setup.inf or the argument.
    # However, during an upgrade, we need to know if we should upgrade the template files or not.
    # For now, the easiest way is to check to if the directory exists, and if is does, we assume we want to upgrade / create the updated scripts.
    if ($inf->{slapd}->{InstScriptsEnabled} eq "true" || -d $inf->{slapd}->{inst_dir} ) {
        debug(1, "Creating or updating instance directory scripts\n");
        # determine initconfig_dir
        my $initconfig_dir = $inf->{slapd}->{initconfig_dir} || get_initconfigdir($inf->{General}->{prefix});

        my %maptable = (
            "DS-ROOT" => $inf->{General}->{prefix},
            "SEP" => "/", # works on all platforms
            "SERVER-NAME" => $inf->{General}->{FullMachineName},
            "SERVER-PORT" => $inf->{slapd}->{ServerPort},
            "PERL-EXEC" => $myperl,
            "DEV-NULL" => $mydevnull,
            "ROOT-DN" => $inf->{slapd}->{RootDN},
            "LDIF-DIR" => $inf->{slapd}->{ldif_dir},
            "SERV-ID" => $inf->{slapd}->{ServerIdentifier},
            "BAK-DIR" => $inf->{slapd}->{bak_dir},
            "SERVER-DIR" => $inf->{General}->{ServerRoot},
            "CONFIG-DIR" => $inf->{slapd}->{config_dir},
            "INITCONFIG-DIR" => $initconfig_dir,
            "INST-DIR" => $inf->{slapd}->{inst_dir},
            "RUN-DIR" => $inf->{slapd}->{run_dir},
            "PRODUCT-NAME" => "slapd",
            "SERVERBIN-DIR" => $inf->{slapd}->{sbindir},
            "DB-DIR" => $inf->{slapd}->{db_dir}
        );


        my $dir = "$inf->{General}->{prefix}/usr/share/dirsrv/script-templates";
        for my $file (glob("$dir/template-*")) {
            my $basename = $file;
            $basename =~ s/^.*template-//;
            my $destfile = "$inf->{slapd}->{inst_dir}/$basename";
            debug(1, "$destfile\n");

            next if ($skip and -f $destfile); # in skip mode, skip files that already exist

            if (!open(SRC, "< $file")) {
                return ("error_opening_scripttmpl", $file, $!);
            }
            if (!open(DEST, "> $destfile")) {
                return ("error_opening_scripttmpl", $destfile, $!);
            }
            my $contents; # slurp entire file into memory
            read SRC, $contents, int(-s $file);
            close(SRC);
            while (my ($key, $val) = each %maptable) {
                $contents =~ s/\{\{$key\}\}/$val/g;
            }
            print DEST $contents;
            close(DEST);
            my @errs = changeOwnerMode($inf, 5, $destfile);
            if (@errs) {
                return @errs;
            }
        }
    } else {
        debug(1, "No instance directory scripts will be updated or created\n");
    }

    return ();
}

sub createConfigFile {
    my $inf = shift;
    my $conffile = "$inf->{slapd}->{config_dir}/dse.ldif";
    my $conn = new FileConn;
    my @errs;

    # first, create the basic config
    my $mapper = new Inf("$inf->{General}->{prefix}/usr/share/dirsrv/inf/dscreate.map");
    my $dsinf = new Inf("$inf->{General}->{prefix}/usr/share/dirsrv/inf/slapd.inf");
    if (!$inf->{slapd}->{ds_bename}) {
        $inf->{slapd}->{ds_bename} = "userRoot"; # for suffix-db
    }
    $mapper = process_maptbl($mapper, \@errs, $inf, $dsinf);
    if (!$mapper or @errs) {
        $conn->close();
        if (!@errs) {
            @errs = ('error_creating_file', $conffile, $!);
        }
        return @errs;
    }

    my @ldiffiles = ("$inf->{General}->{prefix}/usr/share/dirsrv/data/template-dse.ldif",
                     "$inf->{General}->{prefix}/usr/share/dirsrv/data/template-suffix-db.ldif",
                     "$inf->{General}->{prefix}/usr/share/dirsrv/data/template-sasl.ldif");

    # additional configuration LDIF files
    if (exists($inf->{slapd}->{ConfigFile})) {
        if (ref($inf->{slapd}->{ConfigFile})) {
            push @ldiffiles, @{$inf->{slapd}->{ConfigFile}};
        } else {
            push @ldiffiles, $inf->{slapd}->{ConfigFile};
        }
    }

    getMappedEntries($mapper, \@ldiffiles, \@errs, \&check_and_add_entry,
                     [$conn]);

    if (@errs) {
        $conn->close();
        return @errs;
    }

    if ("1") {
        my $ent = $conn->search("cn=config", "base", "(objectclass=*)");
        if (defined($inf->{slapd}->{ldapifilepath})) {
            $ent->setValues("nsslapd-ldapifilepath", $inf->{slapd}->{ldapifilepath});
            $ent->setValues("nsslapd-ldapilisten", "on");
        } else {
            my $parent = dirname($inf->{slapd}->{run_dir});
            $ent->setValues("nsslapd-ldapifilepath",
                            "$parent/slapd-$inf->{slapd}->{ServerIdentifier}.socket");
            $ent->setValues("nsslapd-ldapilisten", "off");
        }
        if ("1") {
            $ent->setValues("nsslapd-ldapiautobind", "off");
            $ent->setValues("nsslapd-ldapimaprootdn", $inf->{slapd}->{RootDN});
            $ent->setValues("nsslapd-ldapimaptoentries", "off");
            $ent->setValues("nsslapd-ldapiuidnumbertype", "uidNumber");
            $ent->setValues("nsslapd-ldapigidnumbertype", "gidNumber");
            $ent->setValues("nsslapd-ldapientrysearchbase", $inf->{slapd}->{Suffix});
            if ("") {
                $ent->setValues("nsslapd-ldapiautodnsuffix", "cn=peercred,cn=external,cn=auth");
            }
        }
        $ent->setValues("nsslapd-defaultNamingContext", $inf->{slapd}->{Suffix});
        if (!$conn->update($ent)) {
            $conn->close();
            return ("error_enabling_feature", "ldapi", $conn->getErrorString());
        }
    }

    if ($inf->{slapd}->{sasl_path}) {
        my $ent = $conn->search("cn=config", "base", "(objectclass=*)");
        $ent->setValues("nsslapd-saslpath", $inf->{slapd}->{sasl_path});
        if (!$conn->update($ent)) {
            $conn->close();
            return ("error_enabling_feature", "sasl_path", $conn->getErrorString());
        }
    }

    if (!$conn->write($conffile)) {
        $conn->close();
        return ("error_writing_ldif", $conffile, $!);
    }
    $conn->close();

    if (@errs = changeOwnerMode($inf, 6, $conffile)) {
        return @errs;
    }
    # make a copy
    my $origconf = "$inf->{slapd}->{config_dir}/dse_original.ldif";
    $! = 0; # clear errno
    copy($conffile, $origconf);
    if ($!) {
        return ('error_copying_file', $conffile, $origconf, $!);
    }
    if (@errs = changeOwnerMode($inf, 4, $origconf)) {
        return @errs;
    }
    
    return @errs;
}

sub makeOtherConfigFiles {
    my $inf = shift;
    my $skip = shift;
    my @errs;
    my %maptable = (
        "DS-ROOT" => $inf->{General}->{prefix},
        "SERVER-DIR" => $inf->{General}->{ServerRoot},
        "CONFIG-DIR" => $inf->{slapd}->{config_dir},
        "INST-DIR" => $inf->{slapd}->{inst_dir},
        "RUN-DIR" => $inf->{slapd}->{run_dir},
        "PRODUCT-NAME" => "slapd",
        "SERVERBIN-DIR" => $inf->{slapd}->{sbindir},
    );

    # install certmap.conf at <configdir>
    my $src = "$inf->{General}->{prefix}/etc/dirsrv/config/certmap.conf";
    my $dest = "$inf->{slapd}->{config_dir}/certmap.conf";
    $! = 0; # clear errno

    #in skip mode, skip files that already exist
    unless ($skip and -f $dest) {
        copy($src, $dest);
        if ($!) {
            return ('error_copying_file', $src, $dest, $!);
        }
        if (@errs = changeOwnerMode($inf, 4, $dest)) {
            return @errs;
        }
    }

    $src = "$inf->{General}->{prefix}/etc/dirsrv/config/slapd-collations.conf";
    $dest = "$inf->{slapd}->{config_dir}/slapd-collations.conf";

    $! = 0; # clear errno

    #in skip mode, skip files that already exist
    unless ($skip and -f $dest) {
        copy($src, $dest);
        if ($!) {
            return ('error_copying_file', $src, $dest, $!);
        }
        if (@errs = changeOwnerMode($inf, 4, $dest)) {
            return @errs;
        }
    }

    # determine initconfig_dir
    my $initconfig_dir = $inf->{slapd}->{initconfig_dir} || get_initconfigdir($inf->{General}->{prefix});

    # install instance specific initconfig script
    $src = "$inf->{General}->{prefix}/etc/dirsrv/config/template-initconfig";
    $dest = "$initconfig_dir/dirsrv-$inf->{slapd}->{ServerIdentifier}";

    $! = 0; # clear errno

    # in skip mode, skip files that already exist
    unless ($skip and -f $dest) {
        if (!open(SRC, "< $src")) {
            return ("error_opening_scripttmpl", $src, $!);
        }
        if (!open(DEST, "> $dest")) {
            return ("error_opening_scripttmpl", $dest, $!);
        }
        my $contents; # slurp entire file into memory
        read SRC, $contents, int(-s $src);
        close(SRC);
        while (my ($key, $val) = each %maptable) {
            $contents =~ s/\{\{$key\}\}/$val/g;
        }
        print DEST $contents;
        close(DEST);
        if (@errs = changeOwnerMode($inf, 4, $dest)) {
            return @errs;
        }
    }

    return ();
}

sub installSchema {
    my $inf = shift;
    my $skip = shift;
    my @errs;
    my @schemafiles = ();
    if (!defined($inf->{slapd}->{install_full_schema}) or
        $inf->{slapd}->{install_full_schema}) {
        push @schemafiles, glob("$inf->{General}->{prefix}/etc/dirsrv/schema/*");
    } else {
        push @schemafiles, "$inf->{General}->{prefix}/etc/dirsrv/schema/00core.ldif",
            "$inf->{General}->{prefix}/etc/dirsrv/schema/01core389.ldif";
    }

    # additional schema files
    if (exists($inf->{slapd}->{SchemaFile})) {
        if (ref($inf->{slapd}->{SchemaFile})) {
            push @schemafiles, @{$inf->{slapd}->{SchemaFile}};
        } else {
            push @schemafiles, $inf->{slapd}->{SchemaFile};
        }
    }
    for my $file (@schemafiles) {
        my $src = $file;
        my $basename = basename($src);
        my $dest = "$inf->{slapd}->{schema_dir}/$basename";

        next if ($skip and -f $dest); # skip files that already exist

        $! = 0; # clear errno
        copy($src, $dest);
        if ($!) {
            return ('error_copying_file', $src, $dest, $!);
        }
        my $mode = 4; # default read only
        if ($basename eq "99user.ldif") {
            $mode = 6; # read write
        }
        if (@errs = changeOwnerMode($inf, $mode, $dest)) {
            return @errs;
        }
    }

    return ();
}

# maps the suffix attr to the filename to use
my %suffixTable = (
    'o' => "/usr/share/dirsrv/data/template-org.ldif",
    'dc' => "/usr/share/dirsrv/data/template-domain.ldif",
    'ou' => "/usr/share/dirsrv/data/template-orgunit.ldif",
    'st' => "/usr/share/dirsrv/data/template-state.ldif",
    'l' => "/usr/share/dirsrv/data/template-locality.ldif",
    'c' => "/usr/share/dirsrv/data/template-country.ldif"
);

sub initDatabase {
    my $inf = shift;
    my $istempldif = 0;
    # If the user has specified an LDIF file to use to initialize the database,
    # load it now
    my $ldiffile = $inf->{slapd}->{InstallLdifFile};
    if ($ldiffile =~ /none/i) {
        debug(1, "No ldif file or org entries specified - no initial database will be created\n");
        return ();
    } elsif ($ldiffile && ($ldiffile !~ /suggest/i)) {
        debug(1, "Loading initial ldif file $ldiffile\n");
        if (! -r $ldiffile) {
            return ('error_opening_init_ldif', $ldiffile);
        }
    } elsif (($inf->{slapd}->{Suffix} =~ /^(.*?)=/) && $suffixTable{$1}) {
        my @errs;
        my $template = $inf->{General}->{prefix} . $suffixTable{$1};
        my $mapper = new Inf("$inf->{General}->{prefix}/usr/share/dirsrv/inf/dsorgentries.map");
        my $dsinf = new Inf("$inf->{General}->{prefix}/usr/share/dirsrv/inf/slapd.inf");
        my @rdns = ldap_explode_dn($inf->{slapd}->{Suffix}, 1);
        $inf->{slapd}->{naming_value} = $rdns[0];
        $mapper = process_maptbl($mapper, \@errs, $inf, $dsinf);
        if (!$mapper or @errs) {
            return @errs;
        }
        
        my @ldiffiles = ($template, "$inf->{General}->{prefix}/usr/share/dirsrv/data/template-baseacis.ldif");
        # default is to create org entries unless explicitly set to none
        if (!exists($inf->{slapd}->{InstallLdifFile}) or
            ($inf->{slapd}->{InstallLdifFile} =~ /suggest/i)) {
            push @ldiffiles, "$inf->{General}->{prefix}/usr/share/dirsrv/data/template.ldif";
        }
        
        my ($fh, $templdif) = tempfile("ldifXXXXXX", SUFFIX => ".ldif", OPEN => 0,
                                       DIR => File::Spec->tmpdir);
        if (!$templdif) {
            return ('error_creating_templdif', $!);
        }
        my $conn = new FileConn;
        $conn->setNamingContext($inf->{slapd}->{Suffix});
        getMappedEntries($mapper, \@ldiffiles, \@errs, \&check_and_add_entry,
                         [$conn]);
        if (@errs) {
            $conn->close();
            return @errs;
        }
        if (!$conn->write($templdif)) {
            $conn->close();
            return ('error_writing_ldif', $templdif, $!);
        }
        $conn->close();
        if (@errs) {
            return @errs;
        }
        if (@errs = changeOwnerMode($inf, 4, $templdif)) {
            unlink($ldiffile);
            return @errs;
        }
        # $templdif now contains the ldif to import
        $ldiffile = $templdif;
        $istempldif = 1;
    }
    if (!$ldiffile) {
        return ();
    }

    my $cmd = "$inf->{slapd}->{sbindir}/ldif2db -Z $inf->{slapd}->{ServerIdentifier} -n $inf->{slapd}->{ds_bename} -i \'$ldiffile\'";
    $? = 0; # clear error condition
    my $output = `$cmd 2>&1`;
    my $result = $?;
    if ($istempldif) {
        unlink($ldiffile);
    }
    if ($result) {
        return ('error_importing_ldif', $ldiffile, $result, $output);
    }

    debug(1, $output);

    return ();
}

sub startServer {
    my $inf = shift;
    return () if (defined($inf->{slapd}->{start_server}) && !$inf->{slapd}->{start_server});

    my @errs;
    # get error log
    my $errLog = "$inf->{slapd}->{log_dir}/errors";
    my $startcmd = "$inf->{slapd}->{sbindir}/start-dirsrv $inf->{slapd}->{ServerIdentifier}";
    if ("/usr/lib/systemd/system" and (getLogin() eq 'root')) {
        $startcmd = "/bin/systemctl start dirsrv\@$inf->{slapd}->{ServerIdentifier}.service";
    }

    # emulate tail -f
    # if the last line we see does not contain "slapd started", try again
    my $done = 0;
    my $started = 0;
    my $code = 0;
    my $lastLine = "";
    my $cmdPat = 'slapd started\.';
    my $timeout = $inf->{slapd}->{startup_timeout};

    $timeout = $timeout?$timeout:600; # default is 10 minutes
    $timeout = time + $timeout;

    debug(1, "Starting the server: $startcmd\n");

    # We have to do this because docker is incapable of sane process management
    # Sadly we have to sacrifice output collection, because of perl issues
    my $cpid = open(my $output, "-|", "$startcmd 2>&1");
    my $code = -512;
    if ($cpid) {
        # Parent process
        waitpid($cpid,0);
        $code = $?;
    }
    close($output);
    if ($code) {
        debug(0, "Process returned $code\n");
    } else {
        debug(1, "Process returned $code\n");
    }

    # try to open the server error log
    my $ii = 0;
    while (time < $timeout) {
        if (open(IN, $errLog)) {
            last;
        }
        sleep(1);
        if (!($ii % 10)) {
            debug(0, "Attempting to obtain server status . . .\n");
        }
        ++$ii;
    }

    if (! -f $errLog) {
        debug(0, "Error: Could not read error log $errLog to get server startup status.  Error: $!\n");
        return ('error_starting_server', $startcmd, "no status", $!);
    }
    if (time >= $timeout) {
        debug(0, "Error: timed out waiting for the server to start and write to $errLog");
        return ('error_starting_server', $startcmd, "timeout", 0);
    }
        
    my $pos = tell(IN);
    my $line;
    while (($done == 0) && (time < $timeout)) {
        for (; ($done == 0) && ($line = <IN>); $pos = tell(IN)) {
            $lastLine = $line;
            debug(1, $line);
            if ($line =~ /$cmdPat/) {
                $done = 1;
                $started = 1;
            } elsif ($line =~ /Initialization Failed/) {
                debug(1, "Server failed to start, retrying . . .\n");
                $code = system($startcmd);
            } elsif ($line =~ /exiting\./) {
                debug(1, "Server failed to start, retrying . . .\n");
                $code = system($startcmd);
            }
        }
        if ($lastLine =~ /PR_Bind/) {
            # server port conflicts with another one, just report and punt
            debug(0, $lastLine);
            @errs = ('error_port_available', $inf->{slapd}->{ServerPort}, $!);
            $done = 1;
        }
        if ($done == 0) {
            # rest a bit, then . . .
            sleep(2);
            # . . . reset the EOF status of the file desc
            seek(IN, $pos, 0);
        }
    }
    close(IN);

    if (!$started) {
        $! = $code;
        my $now = time;
        if ($now > $timeout) {
            debug(0, "Possible timeout starting server: timeout=$timeout now=$now\n");
        }
        @errs = ('error_starting_server', $startcmd, $lastLine, $!);
    } else {
        debug(1, "Your new directory server has been started.\n");
    }
    
    return @errs;
}

sub set_path_attribute {
    my $val = shift;
    my $defaultval = shift;
    my $prefix = shift;

    if ($val) {
        return "$prefix" . "$val";
    } else {
        return "$prefix" . "$defaultval";
    }
}

sub set_localrundir {
    my $val = shift;
    my $prefix = shift;

    if ($val) {
        return "$prefix" . "$val";
    } else {
        return "";
    }
}

sub setDefaults {
    my $inf = shift;
    # set default values

    # this turns off the warnings
    if (!defined($inf->{General}->{prefix})) {
        $inf->{General}->{prefix} = "";
    }

    if (!$inf->{General}->{FullMachineName}) {
        $inf->{General}->{FullMachineName} = hostname();
    }

    if (!$inf->{General}->{SuiteSpotUserID}) {
        if ($> != 0) { # if not root, use the user's uid
            $inf->{General}->{SuiteSpotUserID} = getLogin;
        } else {
            return('error_missing_userid');
        }
    }

    if (!$inf->{General}->{SuiteSpotGroup}) {
        # If the group wasn't specified, use the primary group
        # of the SuiteSpot user
        $inf->{General}->{SuiteSpotGroup} = getGroup($inf->{General}->{SuiteSpotUserID});
    }

    if (!$inf->{slapd}->{RootDN}) {
        $inf->{slapd}->{RootDN} = "cn=Directory Manager";
    }

    if (!$inf->{slapd}->{Suffix}) {
        my $suffix = $inf->{General}->{FullMachineName};
        # convert fqdn to dc= domain components
        $suffix =~ s/^[^\.]*\.//; # just the domain part
        $suffix = "dc=$suffix";
        $suffix =~ s/\./,dc=/g;
        $inf->{slapd}->{Suffix} = $suffix;
    }
    $inf->{slapd}->{Suffix} = normalizeDN($inf->{slapd}->{Suffix});

    if (!$inf->{slapd}->{ServerIdentifier}) {
        my $servid = $inf->{General}->{FullMachineName};
        # strip out the leftmost domain component
        $servid =~ s/\..*$//;
        $inf->{slapd}->{ServerIdentifier} = $servid;
    }

    if ("") {
        $inf->{General}->{ServerRoot} = "$inf->{General}->{prefix}/opt/dirsrv";
    } else {
        $inf->{General}->{ServerRoot} = "$inf->{General}->{prefix}/usr/lib64/dirsrv";
    }

    if (!defined($inf->{slapd}->{sasl_path})) {
        if ($Config{'osname'} ne "linux") {
            $inf->{slapd}->{sasl_path} = "$inf->{General}->{prefix}/usr/lib64/sasl2";
        }
    }

    if (!defined($inf->{slapd}->{ServerPort}) and
        !defined($inf->{slapd}->{ldapifilepath})) {
        if ("1") {
            return ('error_missing_port_and_ldapi');
        } else {
            return ('error_missing_port');
        }
    }

    if (!defined($inf->{slapd}->{ServerPort})) {
        $inf->{slapd}->{ServerPort} = 0;
    }

    $inf->{slapd}->{HashedRootDNPwd} = getHashedPassword($inf->{slapd}->{RootDNPwd});

    $inf->{slapd}->{localstatedir} = set_path_attribute($inf->{slapd}->{localstatedir},
                                                        "/var",
                                                        $inf->{General}->{prefix});
    my $localstatedir = $inf->{slapd}->{localstatedir};
    my $servid = $inf->{slapd}->{ServerIdentifier};
    $inf->{slapd}->{sysconfdir} = set_path_attribute($inf->{slapd}->{sysconfdir},
                                                     "/etc",
                                                     $inf->{General}->{prefix});
    my $sysconfdir = $inf->{slapd}->{sysconfdir};
    $inf->{slapd}->{bindir} = set_path_attribute($inf->{slapd}->{bindir},
                                                 "/usr/bin",
                                                 $inf->{General}->{prefix});
    $inf->{slapd}->{sbindir} = set_path_attribute($inf->{slapd}->{sbindir},
                                                  "/usr/sbin",
                                                  $inf->{General}->{prefix});
    $inf->{slapd}->{datadir} = set_path_attribute($inf->{slapd}->{datadir},
                                                  "/usr/share",
                                                  $inf->{General}->{prefix});

    if (!defined($inf->{slapd}->{InstScriptsEnabled})) {
        $inf->{slapd}->{InstScriptsEnabled} = "true";
    }

    if (!defined($inf->{General}->{StrictHostCheck})) {
        $inf->{General}->{StrictHostCheck} = "true";
    }

    if (!defined($inf->{slapd}->{inst_dir})) {
        $inf->{slapd}->{inst_dir} = "$inf->{General}->{ServerRoot}/slapd-$servid";
    }

    if (!defined($inf->{slapd}->{config_dir})) {
        $inf->{slapd}->{config_dir} = "$inf->{General}->{prefix}/etc/dirsrv/slapd-$servid";
    }
    $ENV{DS_CONFIG_DIR} = $inf->{slapd}->{config_dir};

    if (!defined($inf->{slapd}->{schema_dir})) {
        $inf->{slapd}->{schema_dir} = "$sysconfdir/dirsrv/slapd-$servid/schema";
    }

    if (!defined($inf->{slapd}->{lock_dir})) {
        if ("") {
            $inf->{slapd}->{lock_dir} = "$localstatedir/dirsrv/slapd-$servid/lock";
        } else {
            $inf->{slapd}->{lock_dir} = "$localstatedir/lock/dirsrv/slapd-$servid";
        }
    }

    if (!defined($inf->{slapd}->{log_dir})) {
        if ("") {
            $inf->{slapd}->{log_dir} = "$localstatedir/dirsrv/slapd-$servid/log";
        } else {
            $inf->{slapd}->{log_dir} = "$localstatedir/log/dirsrv/slapd-$servid";
        }
    }

    if (!defined($inf->{slapd}->{run_dir})) {
        if ("") {
            $inf->{slapd}->{run_dir} = "$localstatedir/dirsrv/slapd-$servid/run";
        } else {
            $inf->{slapd}->{run_dir} = "$localstatedir/run/dirsrv";
        }
    }
    $ENV{DS_RUN_DIR} = $inf->{slapd}->{run_dir};

    if (!defined($inf->{slapd}->{db_dir})) {
        if ("") {
            $inf->{slapd}->{db_dir} = "$localstatedir/dirsrv/slapd-$servid/db";
        } else {
            $inf->{slapd}->{db_dir} = "$localstatedir/lib/dirsrv/slapd-$servid/db";
        }
    }

    if (!defined($inf->{slapd}->{bak_dir})) {
        if ("") {
            $inf->{slapd}->{bak_dir} = "$localstatedir/dirsrv/slapd-$servid/bak";
        } else {
            $inf->{slapd}->{bak_dir} = "$localstatedir/lib/dirsrv/slapd-$servid/bak";
        }
    }
    $ENV{DS_BAK_DIR} = $inf->{slapd}->{bak_dir};

    if (!defined($inf->{slapd}->{ldif_dir})) {
        if ("") {
            $inf->{slapd}->{ldif_dir} = "$localstatedir/dirsrv/slapd-$servid/ldif";
        } else {
            $inf->{slapd}->{ldif_dir} = "$localstatedir/lib/dirsrv/slapd-$servid/ldif";
        }
    }

    if (!defined($inf->{slapd}->{tmp_dir})) {
        if ("") {
            $inf->{slapd}->{tmp_dir} = "/tmp";
        } else {
            $inf->{slapd}->{tmp_dir} = "/tmp";
        }
    }
    $ENV{DS_TMP_DIR} = $inf->{slapd}->{tmp_dir};

    if (!defined($inf->{slapd}->{cert_dir})) {
        $inf->{slapd}->{cert_dir} = $inf->{slapd}->{config_dir};
    }

    return ();
}

sub updateSelinuxPolicy {
    my $inf = shift;
    my $mydevnull = (-c "/dev/null" ? " /dev/null " : " NUL ");

    # if selinux is not available, do nothing
    # In perl, exit(1) is 256 from system. ds_selinux_enable returns 1 on true, 0 on false.
    if ((getLogin() eq 'root') and "yes" and system("$inf->{slapd}->{sbindir}/ds_selinux_enabled") == 256 ) {
        debug(1, "Selinux is enabled or permissive, fixing contexts\n");
        # -f "/usr/sbin/sestatus" and !system ("/usr/sbin/sestatus | egrep -i \"selinux status:\\s*enabled\" > $mydevnull 2>&1")) {
        my $localstatedir = $inf->{slapd}->{localstatedir};

        # run restorecon on all of the parent directories we
        # may have created (this only happens if this is the
        # first instance created).
        if ("") {
            system("restorecon -R $localstatedir/dirsrv");
        } else {
            system("restorecon -R $localstatedir/lock/dirsrv");
            system("restorecon -R $localstatedir/log/dirsrv");
            system("restorecon -R $localstatedir/run/dirsrv");
            system("restorecon -R $localstatedir/lib/dirsrv");
        }

        my @inst_dirs = qw(config_dir schema_dir log_dir lock_dir run_dir tmp_dir cert_dir db_dir ldif_dir bak_dir);
        if ($inf->{slapd}->{InstScriptsEnabled} eq "true") {
            @inst_dirs = qw(inst_dir config_dir schema_dir log_dir lock_dir run_dir tmp_dir cert_dir db_dir ldif_dir bak_dir);
        }
        # run restorecon on all instance directories we created
        for my $kw (@inst_dirs) {
            my $dir = $inf->{slapd}->{$kw};
            system("restorecon -R $dir");
        }

        # label the selected port as ldap_port_t
        # We should be doing this for secure port too .....
        if ($inf->{slapd}->{ServerPort} != 0 and not $ENV{DS_SKIP_LABEL}) {
            my $port_query_cmd = ("$inf->{slapd}->{sbindir}/ds_selinux_port_query $inf->{slapd}->{ServerPort} ldap_port_t 2> $mydevnull");
            my $need_label = 0;
            my $result = system($port_query_cmd);

            # 0 is false, 1 is true. True means 'already in policy'.
            if ($result == 0) {
                debug(1, "Port $inf->{slapd}->{ServerPort} must be labeled as ldap_port_t \n");
                $need_label = 1;
            } 
            if ($result == 512) {
                $need_label = 0;
                debug(0, "Port $inf->{slapd}->{ServerPort} already belongs to another selinux type.\n");
                debug(0, " The command below will show you the current type that owns the port.\n");
                debug(0, "sudo $inf->{slapd}->{sbindir}/ds_selinux_port_query $inf->{slapd}->{ServerPort} ldap_port_t\n");
                debug(0, " It is highly likely your server will fail to start ... \n");
            }
            if ($result == 131072) {
                $need_label = 0;
                debug(0, "An error occured running ds_selinux_port_query. This is probably a bug\n");
                debug(0, "$port_query_cmd \n");
            }

            if ($need_label == 1) {
                my $semanage_err;
                my $rc;
                # 60 is a bit excessive, we should fail faster.
                my $retry = 2;
                $ENV{LANG} = "C";
                while (($retry > 0) && ($semanage_err = `semanage port -a -t ldap_port_t -p tcp $inf->{slapd}->{ServerPort} 2>&1`) && ($rc = $?)) {
                    debug(1, "Adding port $inf->{slapd}->{ServerPort} to selinux policy failed - $semanage_err (return code: $rc, $retry attempts remain).\n");
                    debug(1, "Retrying in 5 seconds\n");
                    sleep(5);
                    $retry--;
                }
                if (0 == $retry) {
                    debug(1, "Adding port $inf->{slapd}->{ServerPort} to selinux policy failed - $semanage_err (return code: $rc).\n");
                    debug(1, "Reached time limit.\n");
                }
            }
        }
    }
}

sub updateTmpfilesDotD {
    my $inf = shift;
    my $dir = "/etc/tmpfiles.d";
    my $rundir;
    my $lockdir;
    my $parentdir;

    # if tmpfiles.d is not available, do nothing
    if ((getLogin() eq 'root') and $dir and -d $dir) {
        my $filename = "$dir/dirsrv-$inf->{slapd}->{ServerIdentifier}.conf";
        if (-f $filename) {
            debug(3, "Removing the old tmpfile: $filename\n");
            if (!unlink($filename)){
                debug(1, "Can not delete old tmpfile $filename ($!)\n");
                return();
            }
        }
        debug(3, "Creating $filename\n");
        my $username = "";
        my $groupname = "";
        my $conffile = "$inf->{slapd}->{config_dir}/dse.ldif";
        # use the owner:group from the dse.ldif for the instance
        if (-f $conffile) {
            my ($dev,$ino,$mode,$nlink,$uid,$gid,$rdev,$size,
                $atime,$mtime,$ctime,$blksize,$blocks)
                = stat(_);
            $username = getpwuid($uid);
            if (!$username) {
                debug(1, "Error: could not get username from uid $uid\n");
            }
            $groupname = getgrgid($gid);
        }
        # else, see if we were passed in values to use
        if (!$username) {
            $username = $inf->{General}->{SuiteSpotUserID};
        }
        if (!$groupname) {
            if (defined($inf->{General}->{SuiteSpotGroup})) {
                $groupname = $inf->{General}->{SuiteSpotGroup};
            } else { # $groupname
                $groupname = "-"; # use default
            }
        }
        if (!open(DOTDFILE, ">$filename")) {
            return ( [ 'error_creating_file', $filename, $! ] );
        }
        # Type Path          Mode UID  GID  Age
        # d    /var/run/user 0755 root root 10d
        # we don't use age
        my $localrundir = set_localrundir("/run", $inf->{General}->{prefix});
        if( $localrundir ne "" && -d "$localrundir"){
            $rundir = "$localrundir/dirsrv";
            $lockdir = "$localrundir/lock/dirsrv/slapd-$inf->{slapd}->{ServerIdentifier}";
            $parentdir = "$localrundir/lock/dirsrv";
        } else {
            $rundir = $inf->{slapd}->{run_dir};
            $lockdir = $inf->{slapd}->{lock_dir};
            $parentdir = dirname($inf->{slapd}->{lock_dir});
        }
        print DOTDFILE "d $rundir 0770 $username $groupname\n";
        print DOTDFILE "d $parentdir 0770 $username $groupname\n";
        print DOTDFILE "d $lockdir 0770 $username $groupname\n";

        close DOTDFILE;
    } else {
        debug(3, "no tmpfiles.d - skipping\n");
    }

    return ();
}

sub updateSystemD {
    my $noservicelink = shift;
    my $inf = shift;
    my $unitdir = "/usr/lib/systemd/system";
    my $confbasedir = "/etc/systemd/system";
    my $confdir = "$confbasedir/dirsrv.target.wants";

    if ((getLogin() ne 'root') or !$unitdir or !$confdir or ! -d $unitdir or ! -d $confdir) {
        debug(3, "no systemd - skipping\n");
        return ();
    }

    my @errs = ();
    my $initconfigdir = $inf->{slapd}->{initconfigdir} || get_initconfigdir($inf->{General}->{prefix});
    debug(1, "updating systemd files in $unitdir and $confdir for all directory server instances in $initconfigdir\n");
    my $pkgname = "dirsrv";
    my $changes = 0;
    # installation should already have put down the files and
    # directories - we just need to update the symlinks
    my $servicefile = "$unitdir/$pkgname\@.service";
    # first, look for new instances
    for my $file (glob("$initconfigdir/$pkgname-*")) {
        my $inst = $file;
        $inst =~ s/^.*$pkgname-//;
        # see if this is the admin or snmp or some other service
        if (-f "$unitdir/$pkgname-$inst.service") {
            debug(1, "$unitdir/$pkgname-$inst.service already exists - skipping\n");
            next;
        } elsif (-f "$confbasedir/$pkgname-$inst.service") {
            debug(1, "$confbasedir/$pkgname-$inst.service already exists - skipping\n");
            next;
        } else {
            my $servicelink = "$confdir/$pkgname\@$inst.service";
            if (! -l $servicelink && ! $noservicelink) {
                if (!symlink($servicefile, $servicelink)) {
                    debug(1, "error updating link $servicelink to $servicefile - $!\n");
                    push @errs, [ 'error_linking_file', $servicefile, $servicelink, $! ];
                } else {
                    debug(2, "updated link $servicelink to $servicefile\n");
                }
                $changes++;
            }
        }
    }
    # next, look for instances that have been removed
    for my $file (glob("$confdir/$pkgname\@*.service")) {
        my $inst = $file;
        $inst =~ s/^.*$pkgname\@(.*?).service$/$1/;
        if (! -f "$initconfigdir/$pkgname-$inst") {
            if (!unlink($file)) {
                debug(1, "error removing $file - $!\n");
                push @errs, [ 'error_removing_path', $file, $! ];
            } else {
                debug(2, "removed systemd file $file for removed instance $inst\n");
            }
            $changes++;
        }
    }
    if ($changes > 0) {
        $? = 0;
        my $cmd = '/bin/systemctl --system daemon-reload';
        # run the reload command
        my $output = `$cmd 2>&1`;
        my $status = $?;
        if ($status) {
            debug(1, "Error: $cmd failed - output $output: $!\n");
            push @errs, [ 'error_running_command', $cmd, $output, $! ];
        } else {
            debug(2, "$cmd succeeded\n");
        }
    } else {
        debug(1, "No changes to $unitdir or $confdir\n");
    }
 

    return @errs;
}

sub createDSInstance {
    my $inf = shift;
    my @errs;

    if (@errs = setDefaults($inf)) {
        return @errs;
    }

    if (@errs = sanityCheckParams($inf)) {
        return @errs;
    }

    if (@errs = makeDSDirs($inf)) {
        return @errs;
    }

    if (@errs = createConfigFile($inf)) {
        return @errs;
    }

    if (@errs = makeOtherConfigFiles($inf)) {
        return @errs;
    }

    if (@errs = createInstanceScripts($inf)) {
        return @errs;
    }

    if (@errs = installSchema($inf)) {
        return @errs;
    }

    if (@errs = initDatabase($inf)) {
        return @errs;
    }

    updateSelinuxPolicy($inf);

    if (@errs = updateTmpfilesDotD($inf)) {
        return @errs;
    }

    if (@errs = updateSystemD(0, $inf)) {
        return @errs;
    }

    if (@errs = startServer($inf)) {
        return @errs;
    }

    return @errs;
}

sub stopServer {
    my $instance = shift;
    my $prog = "/usr/sbin/stop-dirsrv";
    if (-x $prog) {
        $? = 0;
        # run the stop command
        my $output = `$prog $instance 2>&1`;
        my $status = $?;
        debug(3, "stopping server $instance returns status $status: output $output\n");
        if ($status) {
            debug(1,"Warning: Could not stop directory server: status $status: output $output\n");
            # if the server is not running, that's ok
            if ($output =~ /not running/) {
                $! = ENOENT;
                return 1;
            }
            # else, some other error (e.g. permission) - return false for error
            return;
        }
    } else {
        debug(1, "stopping server: no such program $prog: cannot stop server\n");
        return;
    }

    debug(1, "Successfully stopped server $instance\n");
    return 1;
}

# NOTE: Returns a list of array ref - each array ref is suitable for passing
# to Resource::getText
sub removeDSInstance {
    my $inst = shift;
    my $force = shift;
    my $all = shift;
    my $initconfig_dir = shift || get_initconfigdir();
    my $baseconfigdir = $ENV{DS_CONFIG_DIR} || "/etc/dirsrv";
    my $instname = "slapd-$inst";
    my $configdir;
    my $rundir;
    my $product_name;
    my @errs;

    my $initconfig = "$initconfig_dir/dirsrv-$inst";
    my $pkglockdir = "/var/lock/dirsrv";
    my $pkgrundir = "/var/run/dirsrv";
    my $pkglibdir = "/var/lib/dirsrv";
    
    # Get the configdir, rundir and product_name from the instance initconfig script.
    unless(open(INFILE, $initconfig)) {
        return ( [ 'error_no_such_instance', $instname, $! ] );
    }

    my $line;
    while($line = <INFILE>) {
        if ($line =~ /CONFIG_DIR=(.*) ; export CONFIG_DIR/) {
            $configdir = $1;
        } elsif ($line =~ /CONFIG_DIR=(.*)$/) {
            $configdir = $1;
        } elsif ($line =~ /RUN_DIR=(.*) ; export RUN_DIR/) {
            $rundir = $1;
        } elsif ($line =~ /RUN_DIR=(.*)$/) {
            $rundir = $1;
        } elsif ($line =~ /PRODUCT_NAME=(.*) ; export PRODUCT_NAME/) {
            $product_name = $1;
        } elsif ($line =~ /PRODUCT_NAME=(.*)$/) {
            $product_name = $1;
        }
    }
    close(INFILE);

    if ( ! -d $configdir )
    {
        debug(1, "Error: $configdir does not exist: $!\n");
        return ( [ 'error_no_such_instance', $configdir, $! ] );
    }
    # read the config file to find out the paths
    my $dseldif = "$configdir/dse.ldif";
    my $conn = new FileConn($dseldif, 1);
    if (!$conn) {
        debug(1, "Error: Could not open config file $dseldif: Error $!\n");
        return ( [ 'error_opening_dseldif', $dseldif, $! ] );
    }

    my $dn = "cn=config";
    my $entry = $conn->search($dn, "base", "(cn=*)", 0);
    if (!$entry)
    {
        debug(1, "Error: Search $dn in $dseldif failed: $entry\n");
        push @errs, [ 'error_finding_config_entry', $dn, $dseldif, $conn->getErrorString() ];
    }

    $dn = "cn=config,cn=ldbm database,cn=plugins,cn=config";
    my $dbentry = $conn->search($dn, "base", "(cn=*)", 0);
    if (!$dbentry)
    {
        debug(1, "Error: Search $dn in $dseldif failed: $dbentry\n");
        push @errs, [ 'error_finding_config_entry', $dn, $dseldif, $conn->getErrorString() ];
    }
    $conn->close();

    # stop the server
    if (!stopServer($inst)) {
        if ($force) {
            debug(1, "Warning: Could not stop directory server - Error: $! - forcing continue\n");
        } elsif ($! == ENOENT) { # stop script not found or server not running
            debug(1, "Warning: Could not stop directory server: already removed or not running\n");
            push @errs, [ 'error_stopping_server', $inst, $! ];
        } else { # real error
            debug(1, "Error: Could not stop directory server - aborting - use -f flag to force removal\n");
            push @errs, [ 'error_stopping_server', $inst, $! ];
            return @errs;
        }
    }

    # remove physical dirs/files
    if ($dbentry) {
        push @errs, remove_tree($dbentry, "nsslapd-directory", $instname, 1);
        push @errs, remove_tree($dbentry, "nsslapd-db-logdirectory", $instname, 1);
    }
    if ($entry) {
        push @errs, remove_tree($entry, "nsslapd-lockdir", $instname, 0);
        push @errs, remove_tree($entry, "nsslapd-tmpdir", $instname, 0);
        push @errs, remove_tree($entry, "nsslapd-bakdir", $instname, 1);
        push @errs, remove_tree($entry, "nsslapd-errorlog", $instname, 1);
    }


    # instance dir
    my $instdir = "";
    if ($entry) {
        foreach my $instdir ( @{$entry->{"nsslapd-instancedir"}} )
        {
            if ( -d $instdir && $instdir =~ /$instname/ )
            {
                # clean up pid files (if any)
                remove_pidfile("STARTPIDFILE", $inst, $instdir, $instname, $rundir, $product_name);
                remove_pidfile("PIDFILE", $inst, $instdir, $instname, $rundir, $product_name);

                my $rc = rmtree($instdir);
                if ( 0 == $rc )
                {
                    push @errs, [ 'error_removing_path', $instdir, $! ];
                    debug(1, "Warning: $instdir was not removed.  Error: $!\n");
                }
            }
        }
    }
    # Finally, config dir
    if ($all) {
        push @errs, remove_tree($entry, "nsslapd-schemadir", $instname, 1);
    } else {
        push @errs, remove_tree($entry, "nsslapd-schemadir", $instname, 1, "\.db\$");
    }

    # Remove the instance specific initconfig script
    if ( -f $initconfig ) {
        my $rc = unlink($initconfig);
        if ( 0 == $rc )
        {
            push @errs, [ 'error_removing_path', $initconfig, $! ];
            debug(1, "Warning: $initconfig was not removed. Error: $!\n");
        }
    }

    my $tmpfilesdir = "/etc/tmpfiles.d";
    my $tmpfilesname = "$tmpfilesdir/dirsrv-$inst.conf";
    if ((getLogin() eq 'root') && $tmpfilesdir && -d $tmpfilesdir && -f $tmpfilesname) {
        my $rc = unlink($tmpfilesname);
        if ( 0 == $rc )
        {
            push @errs, [ 'error_removing_path', $tmpfilesname, $! ];
            debug(1, "Warning: $tmpfilesname was not removed. Error: $!\n");
        }
    }

    # remove the selinux label from the ports if needed
    my $mydevnull = (-c "/dev/null" ? " /dev/null " : " NUL ");
    if ((getLogin() eq 'root') and "yes" and system("/usr/sbin/ds_selinux_enabled") == 256 and not $ENV{DS_SKIP_UNLABEL}) {
        foreach my $port (@{$entry->{"nsslapd-port"}}) 
        {

            my $need_remove_label = 0;
            my $port_query_cmd = ("/usr/sbin/ds_selinux_port_query $port ldap_port_t 2> $mydevnull");
            my $result = system($port_query_cmd);

            if ($result == 256) {
                debug(1, "Port $port may be removed as ldap_port_t \n");
                $need_remove_label = 1;
            } 
            if ($result == 131072) {
                $need_remove_label = 0;
                debug(0, "An error occured running ds_selinux_port_query. This is probably a bug\n");
                debug(0, "$port_query_cmd \n");
            }

            my $semanage_err;
            my $rc;
            my $retry = 5;
            $ENV{LANG} = "C";
            if ($need_remove_label) {
                while (($retry > 0) && ($semanage_err = `semanage port -d -t ldap_port_t -p tcp $port 2>&1`) && ($rc = $?)) {
                    if (($semanage_err =~ /defined in policy, cannot be deleted/) || ($semanage_err =~ /is not defined/)) {
                        $retry = -1;
                    } else {
                        debug(1, "Warning: Port $port not removed from selinux policy correctly, $retry attempts remain.  Error: $semanage_err\n");
                        debug(1, "Retrying in 5 seconds\n");
                        sleep(5);
                        $retry--;
                    }
                }
                if (0 == $retry) {
                    push @errs, [ 'error_removing_port_label', $port, $semanage_err];
                    debug(1, "Warning: Port $port not removed from selinux policy correctly.  Error: $semanage_err\n");
                    debug(1, "Reached time limit.\n");
                }
            }
        }

        foreach my $secureport (@{$entry->{"nsslapd-secureport"}})
        {
            my $need_remove_label = 0;
            my $port_query_cmd = ("/usr/sbin/ds_selinux_port_query $secureport ldap_port_t 2> $mydevnull");
            my $result = system($port_query_cmd);

            if ($result == 256) {
                debug(1, "Port $secureport may be removed as ldap_port_t \n");
                $need_remove_label = 1;
            } 
            if ($result == 131072) {
                $need_remove_label = 0;
                debug(0, "An error occured running ds_selinux_port_query. This is probably a bug\n");
                debug(0, "$port_query_cmd \n");
            }
            my $semanage_err;
            my $rc;
            my $retry = 60;
            $ENV{LANG} = "C";
            if ($need_remove_label) {
                while (($retry > 0) && ($semanage_err = `semanage port -d -t ldap_port_t -p tcp $secureport 2>&1`) && ($rc = $?)) {
                    if (($semanage_err =~ /defined in policy, cannot be deleted/) || ($semanage_err =~ /is not defined/)) {
                        $retry = -1;
                    } else {
                        debug(1, "Warning: Port $secureport not removed from selinux policy correctly.  Error: $semanage_err\n");
                        debug(1, "Retrying in 5 seconds\n");
                        sleep(5);
                        $retry--;
                    }
                }
                if (0 == $retry) {
                    push @errs, [ 'error_removing_port_label', $secureport, $semanage_err];
                    debug(1, "Warning: Port $secureport not removed from selinux policy correctly.  Error: $semanage_err\n");
                    debug(1, "Reached time limit.\n");
                }
            }
        }
    }

    # update systemd files
    push @errs, updateSystemD(0);
    
    # if we got here, report success
    if (@errs) {
        debug(1, "Could not successfully remove $instname\n");
    } else {
        if (!<$pkglockdir/*>){
            # If this was the last instance, remove /var/lock/dirsrv & /var/run/dirsrv
            rmdir $pkglockdir;
            rmdir $pkgrundir;
        }
        debug(1, "Instance $instname removed.\n");
    }

    return @errs;
}

1;

# emacs settings
# Local Variables:
# mode:perl
# indent-tabs-mode: nil
# tab-width: 4
# End:
