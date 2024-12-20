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
# This perl module provides a way to set up a new installation after
# the binaries have already been extracted.  This is typically after
# using native packaging support to install the package e.g. RPM,
# pkgadd, depot, etc.  This script will show the license, readme,
# dsktune, then run the usual setup pre and post installers.
#
##########################

package DSMigration;
use Migration;
use DSUtil;
use Inf;
use DSCreate;
use DSUpdate;

# tempfiles
use File::Temp qw(tempfile tempdir);
use File::Basename qw(basename);

# absolute path handling
use Cwd qw(realpath);

# load perldap
use Mozilla::LDAP::Conn;
use Mozilla::LDAP::Utils qw(normalizeDN);
use Mozilla::LDAP::API qw(ldap_explode_dn);
use Mozilla::LDAP::LDIF;

use Carp;

use Exporter;
@ISA       = qw(Exporter);
@EXPORT    = qw(migrateDS);
@EXPORT_OK = qw(migrateDS);

use strict;

use SetupLog;

# these are the attributes for which we will always use
# the new value, or which do not apply anymore
# for the next major release e.g. when we support migration from the
# current release 1.1.x to 1.2 or 2.0, the old version number will
# become quite important for migration - for example, when migrating
# from older than 1.1 to 1.1.x, we need to add the attributes in the
# table below to the new entry because the attribute didn't exist
# at all in the old server version - however, when migrating from
# e.g. 1.1.x to 2.0, we must preserve the old value - this means
# if the user has deleted the attribute from the entry, we must
# "migrate" that deletion by removing the attribute from the new
# entry
my %ignoreOld =
(
 'nsslapd-errorlog'                => 'nsslapd-errorlog',
 'nsslapd-accesslog'               => 'nsslapd-accesslog',
 'nsslapd-auditlog'                => 'nsslapd-auditlog',
 'nskeyfile'                       => 'nsKeyfile',
 'nscertfile'                      => 'nsCertfile',
 'nsslapd-pluginpath'              => 'nsslapd-pluginPath',
 'nsslapd-plugintype'              => 'nsslapd-pluginType',
 'nsslapd-pluginversion'           => 'nsslapd-pluginVersion',
 'nsslapd-plugin-depends-on-named' => 'nsslapd-plugin-depends-on-named',
# these are new attrs that we should just pass through
 'nsslapd-allow-unauthenticated-binds' => 'nsslapd-allow-unauthenticated-binds',
 'nsslapd-allow-anonymous-access'  => 'nsslapd-allow-anonymous-access',
 'nsslapd-localssf'                => 'nsslapd-localssf',
 'nsslapd-minssf'                  => 'nsslapd-minssf',
 'nsslapd-saslpath'                => 'nsslapd-saslpath',
 'nsslapd-rundir'                  => 'nsslapd-rundir',
 'nsslapd-schemadir'               => 'nsslapd-schemadir',
 'nsslapd-lockdir'                 => 'nsslapd-lockdir',
 'nsslapd-tmpdir'                  => 'nsslapd-tmpdir',
 'nsslapd-certdir'                 => 'nsslapd-certdir',
 'nsslapd-ldifdir'                 => 'nsslapd-ldifdir',
 'nsslapd-bakdir'                  => 'nsslapd-bakdir',
 'nsslapd-instancedir'             => 'nsslapd-instancedir',
 'nsslapd-ldapifilepath'           => 'nsslapd-ldapifilepath',
 'nsslapd-ldapilisten'             => 'nsslapd-ldapilisten',
 'nsslapd-ldapiautobind'           => 'nsslapd-ldapiautobind',
 'nsslapd-ldapimaprootdn'          => 'nsslapd-ldapimaprootdn',
 'nsslapd-ldapimaptoentries'       => 'nsslapd-ldapimaptoentries',
 'nsslapd-ldapiuidnumbertype'      => 'nsslapd-ldapiuidnumbertype',
 'nsslapd-ldapigidnumbertype'      => 'nsslapd-ldapigidnumbertype',
 'nsslapd-ldapientrysearchbase'    => 'nsslapd-ldapientrysearchbase',
 'nsslapd-ldapiautodnsuffix'       => 'nsslapd-ldapiautodnsuffix',
 'numsubordinates'                 => 'numSubordinates',
 # for these, we just want to use the default values, even if they were
 # set in 7.1 or later
 'nsslapd-db-private-import-mem'   => 'nsslapd-db-private-import-mem',
 'nsslapd-import-cache-autosize'   => 'nsslapd-import-cache-autosize',
 # nsslapd-allidsthreshold does not exist anymore
 # the analogous concept is nsslapd-idlistscanlimit for searches
 'nsslapd-allidsthreshold'         => 'nsslapd-allidsthreshold'
);

# these are the obsolete entries we do not migrate
my %ignoreOldEntries =
(
 'cn=presence,cn=plugins,cn=config' => 'cn=presence,cn=plugins,cn=config',
 'cn=aim presence,cn=presence,cn=plugins,cn=config' => 'cn=aim presence,cn=presence,cn=plugins,cn=config',
 'cn=icq presence,cn=presence,cn=plugins,cn=config' => 'cn=icq presence,cn=presence,cn=plugins,cn=config',
 'cn=yahoo presence,cn=presence,cn=plugins,cn=config' => 'cn=yahoo presence,cn=presence,cn=plugins,cn=config'
);


# these are the attributes for which we will always use
# the old value
my %alwaysUseOld =
(
 'aci'      => 'aci'
);

sub getDBVERSION {
    my $olddbdir = shift;
    my $data = shift;

    open DBVERSION, "$olddbdir/DBVERSION" or 
        return ('error_reading_dbversion', $olddbdir, $!);
    my $line = <DBVERSION>;
    close DBVERSION;
    chomp($line);
    @{$data} = split("/", $line);
    return ();
}

sub isOldDatabase {
    my $olddbdir = shift;
    my $errs = shift; # array ref
    # check old DBVERSION file
    my @verinfo;
    if (@{$errs} = getDBVERSION($olddbdir, \@verinfo)) {
        return 0;
    }

    if ((($verinfo[0] =~ /^netscape/i) or ($verinfo[0] =~ /^iplanet/i)) and
        (($verinfo[1] =~ /^6/) or ($verinfo[1] =~ /^5/) or ($verinfo[1] =~ /^4/))) {
        return 1;
    }

    return 0;
}

sub getNewDbDir {
    my ($ent, $attr, $mig, $inst) = @_;
    my $newval;
    my %objclasses = map { lc($_) => $_ } $ent->getValues('objectclass');
    my $cn = $ent->getValues('cn');
    # there is one case where we want to just use the existing db directory
    # that's the case where the user has moved the indexes and/or the
    # transaction logs to different partitions for performance
    # in that case, the old directory will not be the same as the default,
    # and the directory will exist
    # for cross platform, we should just use the new default location
    if (!$mig->{crossplatform}) {
        my $oldval = $ent->getValues($attr);
        my $absoldval = realpath($oldval) || $oldval;
        my $olddefault = "$mig->{actualsroot}/$inst";
        if (-d $absoldval and ($absoldval !~ /^$olddefault/)) {
            debug(2, "Keeping old value [$absoldval] for attr $attr in entry ", $ent->getDN(), "\n");
            return $oldval;
        }
    }
    # otherwise, just use the new default locations
    if ("") {
        if ($objclasses{nsbackendinstance}) {
            $newval = "/var/$mig->{pkgname}/$inst/db/$cn";
        } elsif (lc $cn eq 'config') {
            $newval = "/var/$mig->{pkgname}/$inst/db";
        } elsif (lc $cn eq 'changelog5') {
            $newval = "/var/$mig->{pkgname}/$inst/changelogdb";
        }
    } else {
        if ($objclasses{nsbackendinstance}) {
            $newval = "/var/lib/$mig->{pkgname}/$inst/db/$cn";
        } elsif (lc $cn eq 'config') {
            $newval = "/var/lib/$mig->{pkgname}/$inst/db";
        } elsif (lc $cn eq 'changelog5') {
            $newval = "/var/lib/$mig->{pkgname}/$inst/changelogdb";
        }
    }
    debug(2, "New value [$newval] for attr $attr in entry ", $ent->getDN(), "\n");
    return $newval;
}

sub migrateCredentials {
    my ($ent, $attr, $mig, $inst) = @_;
    my $oldval = $ent->getValues($attr);
    my $qoldval = shellEscape($oldval);

    # Older versions of the server on x86 systems and other systems that do not use network byte order
    # stored the credentials incorrectly.  The first step is to determine if this is the case.  We
    # migrate using the same server root to see if we get the same output as we input.
    debug(3, "In migrateCredentials - see how old credentials were encoded.\n");
    my $testval = `/usr/bin/migratecred -o $mig->{actualsroot}/$inst -n $mig->{actualsroot}/$inst -c $qoldval`;
    chomp($testval);
    if ($testval ne $oldval) { # need to turn on the special flag
        debug(3, "Credentials not encoded correctly.  oldval $oldval not equal to testval $testval.  The value will be re-encoded correctly.\n");
        $ENV{MIGRATE_BROKEN_PWD} = "1"; # decode and re-encode correctly
    }
        
    debug(3, "Executing /usr/bin/migratecred -o $mig->{actualsroot}/$inst -n /etc/dirsrv/$inst -c $qoldval . . .\n");
    my $newval = `/usr/bin/migratecred -o $mig->{actualsroot}/$inst -n /etc/dirsrv/$inst -c $qoldval`;
    chomp($newval);
    delete $ENV{MIGRATE_BROKEN_PWD}; # clear the flag, if set
    debug(3, "Converted old value [$oldval] to new value [$newval] for attr $attr in entry ", $ent->getDN(), "\n");
    return $newval;
}

sub removensState {
    my ($ent, $attr, $mig, $inst) = @_;
    my $newval;

    # nsstate is binary and cannot be migrated cross platform
    if (!$mig->{crossplatform}) {
        $newval = $ent->getValues($attr);
    }

    return $newval;
}

sub migIdlSwitch {
    my ($ent, $attr, $mig, $inst) = @_;
    my $newval;

    # if doing cross platform migration, just use the default value for
    # nsslapd-idl-switch
    # if not doing cross platform, meaning we just use the existing
    # database binaries, we must preserve whatever the old value is
    # unless migrating from 6.21 or earlier, in which case we must
    # be migrating from LDIF, and must use the new idl switch
    if (!$mig->{crossplatform}) {
        # the given entry is the old entry - see if it has the nsslapd-directory
        my $olddbdir = $ent->getValues('nsslapd-db-home-directory') ||
            $ent->getValues('nsslapd-directory') ||
            "$mig->{actualsroot}/$inst/db"; # old default db home directory
        # replace the old sroot value with the actual physical location on the target/dest
        $olddbdir =~ s/^$mig->{actualsroot}/$mig->{oldsroot}/;
        my @errs;
        my $isold = isOldDatabase($olddbdir, \@errs);
        if (@errs) {
            $mig->msg($FATAL, @errs);
            return $newval; # use default new value
        } elsif ($isold) {
            debug(3, "The database in $olddbdir is too old to migrate the idl switch setting\n");
            return $newval; # use default new value
        }

        # else the database could be in the new format already - preserve
        # the user's old value
        $newval = $ent->getValues($attr);
    }

    return $newval;
}

# these are attributes that we have to transform from
# the old value to the new value (e.g. a pathname)
# The key of this hash is the attribute name.  The value
# is an anonymous sub which takes two arguments - the entry
# and the old value.  The return value of the sub is
# the new value
my %transformAttr =
(
 'nsslapd-directory' => \&getNewDbDir,
 'nsslapd-db-logdirectory' => \&getNewDbDir,
 'nsslapd-changelogdir' => \&getNewDbDir,
 'nsds5replicacredentials' => \&migrateCredentials,
 'nsmultiplexorcredentials' => \&migrateCredentials,
 'nsstate' => \&removensState,
 'nsslapd-idl-switch' => \&migIdlSwitch
);

sub copyDatabaseDirs {
    my $srcdir = shift;
    my $destdir = shift;
    my $filesonly = shift;
    my @errs;

    my $isold = isOldDatabase($srcdir, \@errs);
    if (@errs) {
        return @errs;
    } elsif ($isold) {
        return ('error_database_too_old', $srcdir);
    }

    if (-d $srcdir && ! -d $destdir && !$filesonly) {
        debug(1, "Copying database directory $srcdir to $destdir\n");
        if (system ("cp -p -r $srcdir $destdir")) {
            return ('error_copying_dbdir', $srcdir, $destdir, $?);
        }
    } elsif (! -d $srcdir) {
        return ("error_dbsrcdir_not_exist", $srcdir);
    } else {
        debug(1, "The destination directory $destdir already exists, copying files/dirs individually\n");
        $! = 0;
        debug(1, "Removing any existing db files in $destdir\n");
        foreach my $file (glob("$destdir/*")) {
            next if (! -f $file);
            unlink($file);
            if ($!) {
                return ("error_removing_temp_db_files", $destdir, $!);
            }
        }
        foreach my $file (glob("$srcdir/*")) {
            if (-f $file) {
                debug(3, "Copying $file to $destdir\n");
                if (system ("cp -p $file $destdir")) {
                    return ('error_copying_dbfile', $file, $destdir, $?);
                }
            } elsif (-d $file && !$filesonly) {
                debug(3, "Copying $file to $destdir\n");
                if (system ("cp -p -r $file $destdir")) {
                    return ('error_copying_dbdir', $file, $destdir, $?);
                }
            }
        }
    }

    return ();
}

# older versions may use the old Netscape names e.g. Netscape Administration Server
# we have to convert these to the new names e.g. 389 Administration Server
sub migrateNetscapeRoot {
    my $ldiffile = shift;
    my ($fh, $tmpldiffile);
    # create a temp inf file for writing for other processes
    # never overwrite the user supplied inf file
    ($fh, $tmpldiffile) = tempfile("nsrootXXXXXX", UNLINK => 0,
                                   SUFFIX => ".ldif", OPEN => 1,
                                   DIR => File::Spec->tmpdir);
    if (!open( MYLDIF, "$ldiffile" )) {
        debug(1, "Error: Can't open $ldiffile: $!");
        return;
    }
    my $in = new Mozilla::LDAP::LDIF(*MYLDIF);
    while (my $ent = readOneEntry $in) {
        my $dn = $ent->getDN();
        next if (!$dn); # netscaperoot should not have the empty dn
        $dn =~ s/\bNetscape\b/389/g;
        $ent->setDN($dn);
        foreach my $attr (keys %{$ent}) {
            my @vals = $ent->getValues($attr);
            map { s/\bNetscape\b/389/g } @vals;
            $ent->setValues($attr, @vals);
        }
        Mozilla::LDAP::LDIF::put_LDIF($fh, 78, $ent);        
    }
    close( MYLDIF );
    close( $fh );

    return $tmpldiffile;
}

sub fixIntegerIndexes {
    my $mig = shift;
    my $inst_dir = shift;
    my $newdbdir = shift;

    if (!$mig->{integerattrs}) {
        debug(1, "No integer syntax attributes, no indexes fixed\n");
        return ();
    }

    # look at each index file in the db dir
    # if it is on our list of integer attributes,
    # remove it and re-create it
    my $dbname = basename($newdbdir);
    for (glob("$newdbdir/*.db4")) {
        my $indexname = basename($_, '.db4');
        if ($mig->{integerattrs}->{lc $indexname}) {
            $mig->msg($INFO, 'fixing_integer_attr_index', $indexname, $newdbdir);
            debug(1, "Removing file $_\n");
            if (! unlink $_) {
                debug(1, "Error: could not remove file $_: $!\n");
                return ('error_removing_index_file', $_, $!);
            }
            my $cmd = "$inst_dir/db2index -n \"$dbname\" -t \"$indexname\"";
            debug(1, "Re-creating index file $_: $cmd\n");
            $? = 0; # clear error condition
            my $output = `$cmd 2>&1`;
            if ($?) {
                return ('error_recreating_index_file', $_, $output);
            }
            debug(1, $output);
        } else {
            debug(3, "Index $indexname is not for an integer syntax attribute - skipping\n");
        }
    }

    return ();
}

# migrate all of the databases in an instance
sub migrateDatabases {
    my $mig = shift; # the Migration object
    my $inst = shift; # the instance name (e.g. slapd-instance)
    my $src = shift; # a Conn to the source
    my $dest = shift; # a Conn to the dest
    my $olddefault = "$mig->{actualsroot}/$inst/db"; # old default db home directory
    my @errs;

    # the ldif2db command will be in nsslapd-instancedir
    my $cfgent = $dest->search("cn=config", "base", "(objectclass=*)");
    my $inst_dir = $cfgent->getValues('nsslapd-instancedir');
    # first, look for an LDIF file in that directory with the same name as the
    # database
    my $foundldif;
    for (glob("$mig->{oldsroot}/$inst/db/*.ldif")) {
        my $fname = $_;
        my $dbname = basename($fname, '.ldif');
        my $deleteflag = 0;
        if ($fname =~ /NetscapeRoot.ldif$/) {
            $fname = migrateNetscapeRoot($fname);
            if ($fname) {
                # make sure $fname is owned by the server user
                my $cfgent = $dest->search("cn=config", "base", "(objectclass=*)");
                my $user = $cfgent->getValues('nsslapd-localuser');
                my $uid = getpwnam $user;
                chown $uid, -1, $fname;
                $deleteflag = 1;
            } else {
                return ("error_creating_templdif", $!);
            }
        }
        my $cmd = "$inst_dir/ldif2db -n \"$dbname\" -i \"$fname\"";
        debug(1, "migrateDatabases: executing command $cmd\n");
        $? = 0; # clear error condition
        my $output = `$cmd 2>&1`;
        if ($deleteflag) {
            unlink($fname);
        }
        if ($?) {
            return ('error_importing_migrated_db', $fname, $?, $output);
        }
        debug(1, $output);
        $foundldif = 1;
    }

    if ($foundldif) {
        return (); # done - can do nothing else for cross-platform
    } elsif ($mig->{crossplatform}) { # cross platform requires LDIF files
        return ('ldif_required_for_cross_platform', "$mig->{oldsroot}/$inst/db");
    }

    # if no LDIF files, just copy over the database directories
    my $ent = $src->search("cn=ldbm database,cn=plugins,cn=config", "one",
                           "(objectclass=*)");
    if (!$ent) {
        return ("error_reading_olddbconfig", $src->getErrorString());
    }
    # there is one case where we want to just use the existing db directory
    # that's the case where the user has moved the indexes and/or the
    # transaction logs to different partitions for performance
    # in that case, the old directory will not be the same as the default,
    # and the directory will exist
    my $olddefault = "$mig->{actualsroot}/$inst";
    do {
        my $cn = $ent->getValues('cn');
        my %objclasses = map { lc($_) => $_ } $ent->getValues('objectclass');
        if ($cn eq 'config') { # global config
            my $newent = $dest->search($ent->getDN(), "base", "(objectclass=*)");
            my $newdbdir = "";
            if ("") {
                $newdbdir = $newent->getValues('nsslapd-directory') ||
                    "/var/$mig->{pkgname}/$inst/db";
            } else {
                $newdbdir = $newent->getValues('nsslapd-directory') ||
                    "/var/lib/$mig->{pkgname}/$inst/db";
            }
            debug(1, "Found ldbm database plugin config entry ", $ent->getDN(), "\n");
            my $dir = $ent->getValues('nsslapd-directory');
            my $homedir = $ent->getValues('nsslapd-db-home-directory');
            my $logdir = $ent->getValues('nsslapd-db-logdirectory');
            debug(1, "old db dir = $dir homedir = $homedir logdir = $logdir\n");
            my $srcdir = $homedir || $dir || "$olddefault/db";
            if (-d $srcdir and ($srcdir !~ /^$olddefault/)) {
                debug(2, "Not copying database files from [$srcdir]\n");
            } else {
                # replace the old sroot value with the actual physical location on the target/dest
                $srcdir =~ s/^$mig->{actualsroot}/$mig->{oldsroot}/;
                if (@errs = copyDatabaseDirs($srcdir, $newdbdir, 1)) {
                    return @errs;
                }
            }
            if ($logdir && ($logdir ne $srcdir)) {
                if (-d $logdir and ($logdir !~ /^$olddefault/)) {
                    debug(2, "Not copying transaction logs from [$logdir]\n");
                } else {
                    # replace the old sroot value with the actual physical location on the target/dest
                    $newdbdir = $newent->getValues('nsslapd-db-logdirectory') ||
                        $newdbdir;
                    $logdir =~ s/^$mig->{actualsroot}/$mig->{oldsroot}/;
                    if (@errs = copyDatabaseDirs($logdir, $newdbdir, 1)) {
                        return @errs;
                    }
                }
            }
        } elsif ($objclasses{nsbackendinstance}) {
            debug(1, "Found ldbm database instance entry ", $ent->getDN(), "\n");
            my $dir = $ent->getValues('nsslapd-directory');
            # the default db instance directory is
            # $oldroot/$inst/$cn
            debug(1, "old instance $cn dbdir $dir\n");
            my $srcdir = $dir || "$olddefault/db/$cn";
            my $newent = $dest->search($ent->getDN(), "base", "(objectclass=*)");
            my $newdbdir = "";
            if ("") {
                $newdbdir = $newent->getValues('nsslapd-directory') ||
                    "/var/$mig->{pkgname}/$inst/db/$cn";
            } else {
                $newdbdir = $newent->getValues('nsslapd-directory') ||
                    "/var/lib/$mig->{pkgname}/$inst/db/$cn";
            }
            if (-d $srcdir and ($srcdir !~ /^$olddefault/)) {
                debug(2, "Not copying database indexes from [$srcdir]\n");
            } else {
                # replace the old sroot value with the actual physical location on the target/dest
                $srcdir =~ s/^$mig->{actualsroot}/$mig->{oldsroot}/;
                if (@errs = copyDatabaseDirs($srcdir, "$newdbdir")) {
                    return @errs;
                }
                # fix up the integer indexes
                if ($mig->{integerattrs}) {
                    debug(3, "The schema has some integer attributes\n");
                    if (@errs = fixIntegerIndexes($mig, $inst_dir, $newdbdir)) {
                        return @errs;
                    }
                } else {
                    debug(3, "No integer attributes to fix for $newdbdir\n");
                }
            }
        }
    } while ($ent = $src->nextEntry());

    return ();
}

sub migrateChangelogs {
    my $mig = shift; # the Migration object
    my $inst = shift; # the instance name (e.g. slapd-instance)
    my $src = shift; # a Conn to the source
    my $dest = shift; # a Conn to the dest
    my $olddefault = "$mig->{actualsroot}/$inst"; # old default db home directory
    # changelog config entry
    my $oldent = $src->search("cn=changelog5, cn=config", "base", "(objectclass=*)");
    my $newent = $dest->search("cn=changelog5, cn=config", "base", "(objectclass=*)");
    if ($oldent and $newent) { # changelog configured
        my $oldcldir = $oldent->getValues('nsslapd-changelogdir');
        if (-d $oldcldir and ($oldcldir !~ /^$olddefault/)) {
            debug(2, "Not copying changelogdb from [$oldcldir]\n");
        } else {
            # replace the old sroot value with the actual physical location on the target/dest
            $oldcldir =~ s/^$mig->{actualsroot}/$mig->{oldsroot}/;
            my $newcldir = $newent->getValues('nsslapd-changelogdir');
            my @errs = copyDatabaseDirs($oldcldir, $newcldir);
            if (@errs) {
                return @errs;
            }
        }
    }

    return ();
}

sub fixAttrsInEntry {
    my ($ent, $mig, $inst) = @_;
    for my $attr (keys %{$ent}) {
        my $lcattr = lc $attr;
        if ($ignoreOld{$lcattr}) {
            debug(3, "fixAttrsInEntry: ignoring old invalid or obsolete attr $attr\n");
            $ent->remove($attr);
            next;
        } elsif ($transformAttr{$lcattr}) {
            my $newval = &{$transformAttr{$lcattr}}($ent, $attr, $mig, $inst);
            if (!$newval) {
                debug(2, "Removing attribute $attr from entry ", $ent->getDN(), "\n");
                $ent->remove($attr);
            } else {
                debug(2, "Setting new value $newval for attribute $attr in entry ", $ent->getDN(), "\n");
                $ent->setValues($attr, $newval);
            }
        } # else just keep as is
    }
}

sub mergeEntries {
    my ($old, $new, $mig, $inst) = @_;
    my %inoldonly; # attrs in old entry but not new one
    my %innewonly; # attrs in new entry but not old one
    my @attrs; # attrs common to old and new
    # if the attribute exists in the old entry but not the new one
    # we should probably add it (checking for special cases first)
    # if the attribute exists in the new entry but not the old one
    # we might have to delete it from the new entry
    # first, get a list of all attributes
    foreach my $attr (keys %{$old}) {
        if (! $new->exists($attr)) {
            $inoldonly{$attr} = $attr;
        } else {
            push @attrs, $attr;
        }
    }
    foreach my $attr (keys %{$new}) {
        if (! $old->exists($attr)) {
            $innewonly{$attr} = $attr;
        }
    }
            
    # iterate through the attr lists
    my $cn = lc $new->getValues("cn");
    foreach my $attr (keys %inoldonly, keys %innewonly, @attrs) {
        debug(3, "mergeEntries: merging entry ", $old->getDN(), " attr $attr\n");
        my $lcattr = lc $attr;
        if ($ignoreOld{$lcattr}) {
            debug(3, "mergeEntries: ignoring old invalid or obsolete attr $attr\n");
            next; # use new value or just omit if attr is obsolete
        } elsif ($transformAttr{$lcattr}) {
            # only transform if the value is in the old entry
            if (!$innewonly{$attr}) {
                my $oldval = $old->getValues($attr);
                my $newval = &{$transformAttr{$lcattr}}($old, $attr, $mig, $inst);
                if (!$newval) {
                    debug(3, "Removing attribute $attr from entry ", $new->getDN(), "\n");
                    $new->remove($attr);
                } else {
                    debug(3, "Setting new value $newval for attribute $attr in entry ", $new->getDN(), "\n");
                    $new->setValues($attr, $newval);
                }
            }
        } elsif ($cn eq "internationalization plugin" and $lcattr eq "nsslapd-pluginarg0") {
            debug(3, "mergeEntries: using new value of internationalization plugin nsslapd-pluginarg0\n");
            next; # use the new value of this path name
        } elsif ($cn eq "referential integrity postoperation" and $lcattr eq "nsslapd-pluginarg1") {
            debug(3, "mergeEntries: using new value of referential integrity postoperation nsslapd-pluginarg1\n");
            next; # use the new value of this path name
        } elsif ($innewonly{$attr}) {
            debug(3, "mergeEntries: removing attr $attr from new entry\n");
            $new->remove($attr); # in new but not old - just remove it
        } else {
            my $oldval = $old->getValues($attr);
            my $newval = $new->getValues($attr);
            $new->setValues($attr, $old->getValues($attr)); # use old value
            debug(3, "mergeEntries: using old val $oldval instead of new val $newval\n");
        }
    }
}

my @allattrlist = ('*', 'aci', 'createTimestamp', 'creatorsName',
                   'modifyTimestamp', 'modifiersName');

sub getAllEntries {
    my $conn = shift;
    my $href = shift;
    my $aref = shift;

    # these are the special DSEs for which we only need ACIs
    for my $dn ("", "cn=monitor", "cn=config") {
        my $scope = $dn ? "sub" : "base";
        my @attrlist;
        if ($dn eq "cn=config") {
            @attrlist = @allattrlist;
        } else {
            @attrlist = qw(aci);
        }
        my $ent = $conn->search($dn, $scope, "(objectclass=*)", 0, @attrlist);
        next if (!$ent or ($conn->getErrorCode() eq 32));
        if ($conn->getErrorCode()) {
            return ('error_reading_entry', $dn, $conn->getErrorString());
        }
        do {
            my $ndn = normalizeDN($ent->getDN());
            $href->{$ndn} = $ent;
            push @{$aref}, $ndn;
        } while ($ent = $conn->nextEntry());
    }

    return ();
}

# these entries cannot be migrated if doing cross platform
my %noCrossPlatformDN = (
    'cn=uniqueid generator,cn=config' => 'cn=uniqueid generator,cn=config'
);

sub mergeConfigEntries {
    my $mig = shift; # the Migration object
    my $inst = shift; # the instance name (e.g. slapd-instance)
    my $src = shift; # a Conn to the source
    my $dest = shift; # a Conn to the dest

    # first, read in old file
    my %olddse; # map of normalized DN to Entry
    my @olddns; # the DNs in their original order
    my @errs;
    if (@errs = getAllEntries($src, \%olddse, \@olddns)) {
        return @errs;
    }

    # next, read in new file
    my %newdse; # map of normalized DN to Entry
    my @allnewdns;
    my @newdns; # the DNs in their original order that are not in olddns
    if (@errs = getAllEntries($dest, \%newdse, \@allnewdns)) {
        return @errs;
    }

    for my $ndn (@allnewdns) {
        if (! exists $olddse{$ndn}) {
            push @newdns, $ndn;
        }
    }

    # now, compare entries
    # if the entry exists in the old tree but not the new, add it
    # if the entry exists in the new tree but not the old, delete it
    # otherwise, merge the entries
    # @olddns contains the dns in the old dse.ldif, including ones that
    # may also be in the new dse.ldif
    # @newdns contains dns that are only in the new dse.ldif
    for my $dn (@olddns, @newdns) {
        my $oldent = $olddse{$dn};
        my $newent = $newdse{$dn};
        my $op;
        my $rc = 1;
        if ($mig->{crossplatform} && $noCrossPlatformDN{$dn}) {
            debug(1, "Cannot migrate the entry $dn - skipping\n");
            next;
        } elsif ($oldent && !$newent) {
            if (!$ignoreOldEntries{$dn}) {  # make sure it's not obsolete
                # may have to fix up some values in the old entry
                fixAttrsInEntry($oldent, $mig, $inst);
                $rc = $dest->add($oldent);
                $op = "add";
            } else {
                debug(2, "Ignoring entry $dn - configuration not supported\n");
            }
        } elsif (!$oldent && $newent) {
            if ($dn =~ /o=deleteAfterMigration/i) {
                $rc = $dest->delete($dn);
                $op = "delete";
            } else {
                # do nothing - no change to entry
            }
        } else { #merge
            # $newent will contain the merged entry
            mergeEntries($oldent, $newent, $mig, $inst);
            $rc = $dest->update($newent);
            $op = "update";
        }
        
        if (!$rc) {
            return ('error_updating_merge_entry', $op, $dn, $dest->getErrorString());
        }
    }

    return ();
}

my %deletedschema = (
    '50ns-calendar'        => '50ns-calendar.ldif',
    '50ns-compass'         => '50ns-compass.ldif',
    '50ns-delegated-admin' => '50ns-delegated-admin.ldif',
    '50ns-legacy'          => '50ns-legacy.ldif',
    '50ns-mail'            => '50ns-mail.ldif',
    '50ns-mcd-browser'     => '50ns-mcd-browser.ldif',
    '50ns-mcd-config'      => '50ns-mcd-config.ldif',
    '50ns-mcd-li'          => '50ns-mcd-li.ldif',
    '50ns-mcd-mail'        => '50ns-mcd-mail.ldif',
    '50ns-media'           => '50ns-media.ldif',
    '50ns-mlm'             => '50ns-mlm.ldif',
    '50ns-msg'             => '50ns-msg.ldif',
    '50ns-netshare'        => '50ns-netshare.ldif',
    '50ns-news'            => '50ns-news.ldif',
    '50ns-proxy'           => '50ns-proxy.ldif',
    '50ns-wcal'            => '50ns-wcal.ldif',
    '51ns-calendar'        => '51ns-calendar.ldif'
);

# these indexes are handled specially by the db code
my %intattrstoskip = (
    'numsubordinates' => 'numSubordinates',
    'hassubordinates' => 'hasSubordinates'
);

sub fixup99user {
    my $mig = shift; # the Migration object
    my $inst = shift; # The name of the instance
    my $newschemadir = shift; # the new instance's schema path

    my %attrstoskip = ();
    my %objclassestoskip = ();
    my $uid;
    my $gid;
    my $mode;

    # Read every schema file in the legacy server's schema directory
    for (glob("$mig->{oldsroot}/$inst/config/schema/*.ldif")) {
        if (!open( OLDSCHEMA, $_ )) {
                debug(0, "Can't open schema file $_: $!\n");
                next;
        }

        # Read attributes from each file, looking for ones that contain
        # the string "DESC ''".
        my $in = new Mozilla::LDAP::LDIF(*OLDSCHEMA);
        while (my $ent = readOneEntry $in) {
            my @attrs = $ent->getValues('attributeTypes');
            my @objclasses = $ent->getValues('objectClasses');
            foreach my $attr (@attrs) {
                debug(4, "Checking if attribute should be added to skip list ($attr)\n");
                if ($attr =~ /\(\s*(\S*)\s*NAME .* DESC \'\'/) {
                    # Store the OID of those in an associative array for
                    # quick lookups later.
                    debug(3, "Adding attribute to list to skip (OID $1)\n");
                    $attrstoskip{"$1"} = 1;
                }
            }

            foreach my $objclass (@objclasses) {
                debug(4, "Checking if objectclass should be added to skip list ($objclass)\n");
                if ($objclass =~ /\(\s*(\S*)\s*NAME .* DESC \'\'/) {
                    # Store the OID of those in an associative array for
                    # quick lookups later.
                    debug(3, "Adding objectclass to list to skip (OID $1)\n");
                    $objclassestoskip{"$1"} = 1;
                }
            }
        }

        close(OLDSCHEMA);
    }

    # Open the 99user.ldif file in the new server schema directory, which is a
    # copy of the one in the legacy server.  Also open a tempfile.
    if (!open(USERSCHEMA, "$newschemadir/99user.ldif")) {
        return ("error_opening_schema", "$newschemadir/99user.ldif", $!);
    }

    # Open a tempfile to write the cleaned 99user.ldif to
    if (!open(TMPSCHEMA, ">$newschemadir/99user.ldif.tmp")) {
        close(USERSCHEMA);
        return ("error_opening_schema", "$newschemadir/99user.ldif.tmp", $!);
    }

    # Iterate through every attribute in the 99user.ldif file and write them to the
    # tempfile if their OID doesn't exist in the "bad schema" array.
    my $in = new Mozilla::LDAP::LDIF(*USERSCHEMA);
    while (my $ent = readOneEntry $in) {
        my @attrs = $ent->getValues('attributeTypes');
        my @objclasses = $ent->getValues('objectClasses');
        my @keepattrs;
        my @keepobjclasses;
        foreach my $attr (@attrs) {
            if ($attr =~ /\(\s*(\S*)\s*NAME/) {
                debug(3, "Checking if attribute should be trimmed (OID $1)\n");
                # See if this OID is in our list of attrs to skip
                if ($attrstoskip{"$1"}) {
                    debug(2, "Trimming attribute from 99user.ldif (OID $1)\n");
                    next;
                }
            }

            # Keep this value
            debug(3, "Keeping attribute in 99user.ldif (OID $1)\n");
            push @keepattrs, $attr;
        }

        foreach my $objclass (@objclasses) {
            if ($objclass =~ /\(\s*(\S*)\s*NAME/) {
                debug(3, "Checking if objectclass should be trimmed (OID $1)\n");
                # See if this OID is in our list of objectclasses to skip
                if ($objclassestoskip{"$1"}) {
                    debug(2, "Trimming objectclass from 99user.ldif (OID $1)\n");
                    next;
                }
            }

            # Keep this value
            debug(3, "Keeping objectclass in 99user.ldif (OID $1)\n");
            push @keepobjclasses, $objclass;
        }

        # Update the entry with the values we want to keep
        if ($#keepattrs >= $[) {
            $ent->setValues("attributetypes", @keepattrs);
        } else {
            $ent->remove("attributetypes");
        }

        if ($#keepobjclasses >= $[) {
            $ent->setValues("objectclasses", @keepobjclasses);
        } else {
            $ent->remove("objectclasses");
        }

        # Write the entry to temp schema file
        my $oldfh = select(TMPSCHEMA);
        $ent->printLDIF();
        select($oldfh);
    }

    close(USERSCHEMA);
    close(TMPSCHEMA);

    # Make the ownership and permissions on the temp schema file
    # the same as the copied 99user.ldif.
    ($mode, $uid, $gid) = (stat("$newschemadir/99user.ldif"))[2,4,5];
    if ((chown $uid, $gid, "$newschemadir/99user.ldif.tmp") != 1) {
        return ("error_schema_permissions", "$newschemadir/99user.ldif.tmp", $!);
    }

    if ((chmod $mode, "$newschemadir/99user.ldif.tmp") != 1) {
        return ("error_schema_permissions", "$newschemadir/99user.ldif.tmp", $!);
    }

    # Replace the copied 99user.ldif with the trimmed file.
    if ((rename "$newschemadir/99user.ldif.tmp", "$newschemadir/99user.ldif") != 1) {
        return ("error_renaming_schema", "$newschemadir/99user.ldif.tmp", "$newschemadir/99user.ldif", $!);
    }

    return();
}

sub migrateSchema {
    my $mig = shift; # the Migration object
    my $inst = shift; # the instance name (e.g. slapd-instance)
    my $src = shift; # a Conn to the source
    my $dest = shift; # a Conn to the dest

    my @errs;
    my $cfgent = $dest->search("cn=config", "base", "(objectclass=*)");
    my $newschemadir = $cfgent->getValues('nsslapd-schemadir') ||
        "$mig->{configdir}/$inst/schema";
    my %newschema = map {basename($_, '.ldif') => $_} glob("$newschemadir/*.ldif");
    delete $newschema{"99user"}; # always copy this one
    for (glob("$mig->{oldsroot}/$inst/config/schema/*.ldif")) {
        my $fname = basename($_, '.ldif');
        next if ($deletedschema{$fname}); # don't copy deleted schema
        next if ($newschema{$fname}); # use new version
        if (system("cp -p $_ $newschemadir")) {
            return ("error_migrating_schema", $_, $!);
        }
    }

    # fixup any attributes with missing descriptions in 99user.ldif
    if (@errs = fixup99user($mig, $inst, $newschemadir)) {
        return @errs;
    }

    if (!$mig->{crossplatform}) {
        # now, for all of the new schema, we need to get the list of attribute
        # types with INTEGER syntax, including derived types (e.g. SUP 'attr')
        # not required for cross platform because import of the old ldif file
        # will automatically recreate all indexes
        my %intattrs = ();
        for (glob("$newschemadir/*.ldif")) {
            # read in schema entry from LDIF
            if (!open( MYSCHEMA, $_ )) {
                debug(0, "Can't open schema file $_: $!\n");
                next;
            }
            my $in = new Mozilla::LDAP::LDIF(*MYSCHEMA);
            while (my $ent = readOneEntry $in) {
                my @attrs = $ent->getValues('attributeTypes');
                foreach my $attr (@attrs) {
                    # first see if the attribute definition uses INTEGER syntax
                    # else see if the super uses INTEGER - note this assumes the attributes
                    # are listed in the files in SUP order - that is, an attribute does
                    # not reference a SUP before it is defined
                    if ($attr =~ / NAME (?:\(\s)?[\']?(\w+)[\']?.* SYNTAX 1.3.6.1.4.1.1466.115.121.1.27[\{\s]/) {
                        next if ($intattrstoskip{lc $1});
                        $intattrs{lc $1} = $1;
                    } elsif (($attr =~ / NAME (?:\(\s)?[\']?(\w+)[\']?.*SUP [\']?(\w+)[\']?/) &&
                             $intattrs{lc $2}) {
                        next if ($intattrstoskip{lc $1});
                        $intattrs{lc $1} = $1;
                    }
                }
            }
            close MYSCHEMA;
        }
        # %intattrs now contains all of the integer valued attributes
        $mig->{integerattrs} = \%intattrs; # hashref
    }

    return ();
}

sub migrateDSInstance {
    my $mig = shift; # the Migration object
    my $inst = shift; # the instance name (e.g. slapd-instance)
    my $src = shift; # a Conn to the source
    my $dest = shift; # a Conn to the dest

    my @errs;
    # first, merge dse ldif
    if (@errs = mergeConfigEntries($mig, $inst, $src, $dest)) {
        return @errs;
    }

    # next, grab the old schema
    if (@errs = migrateSchema($mig, $inst, $src, $dest)) {
        return @errs;
    }

    if (@errs = updateDS($mig)) {
        return @errs;
    }

    # next, the databases
    if (@errs = migrateDatabases($mig, $inst, $src, $dest)) {
        return @errs;
    }

    # next, the changelogs
    if (!$mig->{crossplatform}) {
        if (@errs = migrateChangelogs($mig, $inst, $src, $dest)) {
            return @errs;
        }
    }

    # next, the security files
    my $cfgent = $dest->search("cn=config", "base", "(objectclass=*)");
    my $newcertdir = $cfgent->getValues("nsslapd-certdir") ||
        "/etc/dirsrv/$inst";
    $mig->migrateSecurityFiles($inst, $newcertdir);

    return @errs;
}

sub migrateDS {
    my $mig = shift;
    my @errs;

    # migration needs to know the instance directory for the directory
    # servers - this assumes they are all in the same place
    if (!$mig->{ServerRoot}) {
        if ("") {
            $mig->{ServerRoot} = "$mig->{inf}->{General}->{prefix}/opt/dirsrv";
        } else {
            $mig->{ServerRoot} = "$mig->{inf}->{General}->{prefix}/usr/lib64/dirsrv";
        }
    }

    # for each instance
    foreach my $inst (@{$mig->{instances}}) {
        if (-f "$mig->{configdir}/$inst/dse.ldif") {
            $mig->msg($WARN, 'instance_already_exists', "$mig->{configdir}/$inst/dse.ldif");
            next;
        }

        # you could theoretically make this work with either a remote source or
        # remote dest
        # $mig->{inf} would contain an entry for each instance e.g.
        # $mig->{inf}->{$inst}
        # each instance specific entry would contain a {General} and a {slapd}
        # all the information necessary to open an LDAP::Conn to the server
        # if the source, you could also change createInfFromConfig to read
        # the info from the Conn (or FileConn) that's needed to create the
        # instance on the dest

        # extract the information needed for ds_newinst.pl
        my $oldconfigdir = "$mig->{oldsroot}/$inst/config";
        my $inf = createInfFromConfig($oldconfigdir, $inst, \@errs);
        if (@errs) {
            $mig->msg(@errs);
            return 0;
        }
        if (!$inf) {
            $mig->msg($FATAL, 'error_opening_dseldif', "$oldconfigdir/dse.ldif", $!);
            return 0;
        }
        debug(2, "Using inf created from $oldconfigdir\n");

        # create servers but do not start them until after databases
        # have been migrated
        $inf->{slapd}->{start_server} = 0;

        # create the new instance
        @errs = createDSInstance($inf);
        if ($inf->{filename}) {
            unlink($inf->{filename});
        }
        if (@errs) {
            $mig->msg(@errs);
            $mig->msg($FATAL, 'error_creating_dsinstance', $inst);
            goto cleanup;
        } else {
            $mig->msg('created_dsinstance', $inst);
        }

        my $src = new FileConn("$oldconfigdir/dse.ldif", 1); # read-only
        if (!$src) {
            $mig->msg($FATAL, 'error_opening_dseldif', "$oldconfigdir/dse.ldif", $!);
            goto cleanup;
        }
        my $dest = new FileConn("$mig->{configdir}/$inst/dse.ldif");
        if (!$dest) {
            $src->close();
            $mig->msg($FATAL, 'error_opening_dseldif', "$mig->{configdir}/$inst/dse.ldif", $!);
            goto cleanup;
        }

        @errs = migrateDSInstance($mig, $inst, $src, $dest);
        $src->close();
        $dest->close();
        if (@errs) {
            $mig->msg(@errs);
            goto cleanup;
        }

	# ensure any selinux relabeling gets done if needed
        DSCreate::updateSelinuxPolicy($inf);

	# do the tmpfiles.d stuff
        @errs = DSCreate::updateTmpfilesDotD($inf);
        if (@errs) {
            $mig->msg(@errs);
            goto cleanup;
        }

	# do the systemd stuff
        @errs = DSCreate::updateSystemD(0, $inf);
        if (@errs) {
            $mig->msg(@errs);
            goto cleanup;
        }

        # finally, start the server
        if ($mig->{start_servers}) {
            $inf->{slapd}->{start_server} = 1;
            if (@errs = DSCreate::startServer($inf)) {
                $mig->msg(@errs);
                goto cleanup;
            }
        }

        next;

cleanup:
        if (-d "$mig->{configdir}/$inst") {
            @errs = removeDSInstance($inf->{slapd}->{ServerIdentifier}, 1, "" ,"", $mig->{inf}->{General}->{prefix} );
            if (@errs) {
                $mig->msg(@errs);
            }
        }
        return 0;
    }

    return 1;
}

#############################################################################
# Mandatory TRUE return value.
#
1;

# emacs settings
# Local Variables:
# mode:perl
# indent-tabs-mode: nil
# tab-width: 4
# End:
