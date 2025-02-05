# BEGIN COPYRIGHT BLOCK
# Copyright (C) 2007 Red Hat, Inc.
# All rights reserved.
#
# License: GPL (version 3 or any later version).
# See LICENSE for details. 
# END COPYRIGHT BLOCK
#

package DSUtil;

use Mozilla::LDAP::Conn;
use Mozilla::LDAP::Utils qw(normalizeDN);
use Mozilla::LDAP::API qw(:constant ldap_explode_dn ldap_err2string) ; # Direct access to C API
use Mozilla::LDAP::LDIF;
use File::Spec::Functions qw(rel2abs);
use File::Spec;
use File::Basename;

require Exporter;
@ISA       = qw(Exporter);
@EXPORT    = qw(portAvailable getAvailablePort isValidDN addSuffix getMappedEntries
                process_maptbl check_and_add_entry getMappedEntries addErr
                getHashedPassword debug createInfFromConfig shellEscape
                isValidServerID isValidUser isValidGroup makePaths getLogin getGroup
                remove_tree remove_pidfile setDebugLog checkHostname serverIsRunning);
@EXPORT_OK = qw(portAvailable getAvailablePort isValidDN addSuffix getMappedEntries
                process_maptbl check_and_add_entry getMappedEntries addErr
                getHashedPassword debug createInfFromConfig shellEscape
                isValidServerID isValidUser isValidGroup makePaths getLogin getGroup
                remove_tree remove_pidfile setDebugLog checkHostname serverIsRunning);

use strict;

my $sockVersion;
BEGIN {
    use Socket;
    $sockVersion = Socket->VERSION;
    if ($sockVersion >= 2.000) {
        import Socket qw ( :addrinfo inet_ntoa 
                       unpack_sockaddr_in unpack_sockaddr_in6 
                       AF_INET INADDR_ANY 
                       PF_INET SO_REUSEADDR SOCK_STREAM SOL_SOCKET );
    } elsif (eval {require Socket6; 1}) {
        import Socket6 qw (getaddrinfo getnameinfo unpack_sockaddr_in6);
    }
}
$sockVersion = Socket->VERSION;
use NetAddr::IP::Util qw( ipv6_n2x );

use File::Temp qw(tempfile tempdir);
use File::Basename qw(dirname);
use File::Path qw(rmtree);

use Carp;

$DSUtil::debuglevel = 0;
$DSUtil::log = 0;

# use like this:
# debug(3, "message");
# this will only print "message" if $debuglevel is 3 or higher (-ddd on the command line)
sub debug {
    my ($level, @rest) = @_;
    if ($level <= $DSUtil::debuglevel) {
        print STDERR "+" x $level, @rest;
        if ($DSUtil::log) {
            $DSUtil::log->logDebug(@rest);
        }
    }
}

sub setDebugLog {
    $DSUtil::log = shift;
}

# return true if the given port number is available, false otherwise
sub portAvailable {
    my $port = shift;
    my $proto = getprotobyname('tcp');
    my $rc = socket(SOCK, PF_INET, SOCK_STREAM, $proto);
    if ($rc == 1) {
        setsockopt(SOCK, SOL_SOCKET, SO_REUSEADDR, 1);
        $rc = bind(SOCK, sockaddr_in($port, INADDR_ANY));
    }
    close(SOCK);
    return $rc and ($rc == 1);
}

# returns a randomly assigned port number, or -1
# if not able to find an available port
sub getAvailablePort {
    my $MINPORT = 1024;
    my $MAXPORT = 65535;

    srand( time() ^ ($$ + ($$ << 15)) );
    while (1) {
        my $port = $MINPORT + int(rand($MAXPORT-$MINPORT));

        if (portAvailable($port)) {
            return $port;
        }
    }
}

sub isValidDN {
    my $dn = shift;
    return ($dn =~ /^[0-9a-zA-Z_-]+=.*$/);
}

sub isValidServerID {
    my $servid = shift;
    my $validchars = '#%:\w@_-';
    if($servid eq "admin"){
        # "admin" is reserved for the admin server
        return 0;
    } else {
        return $servid =~ /^[$validchars]+$/o;
    }
}

# we want the name of the effective user id of this process e.g. if someone did
# an su root, we want getLogin to return "root" not the originating id (getlogin)
# in perl, $> is the effective numeric user id - we need to turn it into a string
# use confess here because if we cannot determine the user, something is really,
# really wrong and we need to abort immediately
sub getLogin {
    return (getpwuid($>))[0] || $ENV{USER} || confess "Error: could not determine the current user ID: $!";
}

# Look up the primary group name for the supplied user
sub getGroup {
    my $user = shift;
    my @userinfo = getpwnam($user);
    
    if(!@userinfo){
        confess "Error: could not find user ID ($user): $!";
    }
   
    return (getgrgid($userinfo[3]))[0] || confess "Error: could not determine the current group name from gid ($userinfo[3]): $!";
}

sub isValidUser {
    my $user = shift;
    # convert numeric uid to string
    my $strans = $user;
    if ($user =~ /^\d+$/) { # numeric - convert to string
        $strans = getpwuid $user;
        if (!$strans) {
            return ("dialog_ssuser_error", $user);
        }
    }
    if ($> != 0) { # if not root, the user must be our uid
        my $username = getLogin;
        if ($strans ne $username) {
            return ("dialog_ssuser_must_be_same", $username);
        }
    } else { # user is root - verify id
        my $nuid = getpwnam $strans;
        if (!defined($nuid)) {
            return ("dialog_ssuser_error", $user);
        }
        if (!$nuid) {
            debug(0, "Warning: using root as the server user id.  You are strongly encouraged to use a non-root user.\n");
        }
    }

    return ();
}

sub isValidGroup {
    my $group = shift;
    my $ngid;
    # convert numeric gid to string
    my $strans = $group;
    if ($group =~ /^\d+$/) { # numeric - convert to string
        $strans = (getgrgid($group))[0];
        if (!$strans) {
            return ("dialog_ssgroup_error", $group);
        }
    }
    # ensure the specified group is a defined group
    $ngid = getgrnam $strans;
    if (!defined($ngid)) {
        return ("dialog_ssgroup_error", $group);
    }
    
    return ();
}

# arguments
# - hostname - the hostname to look for
# - res - the Resource object to use to construct messages
# returns - the error message string, or "" upon success if $res exists
#         - the error message array, or () upon success otherwise
sub checkHostname {
    my $hn = shift;
    my $res = shift;

    # see if hostname is an fqdn
    if ($hn !~ /\./) {
        if ($res) {
            return $res->getText('warning_hostname_not_fully_qualified', $hn);
        } else {
            return ('warning_hostname_not_fully_qualified', $hn);
        }
    }

    # see if we can resolve the hostname (IPv6 supported)
    my $found = 0;
    my @hostip = ();
    if ($sockVersion >= 2.000) {
        debug(1, "Socket version $sockVersion\n");
        my %hints = (socktype => SOCK_STREAM);
        my ($err, @aires) = getaddrinfo($hn, "ldap", \%hints);
        if ($err) {
            if ($res) {
                return $res->getText('warning_no_such_hostname', $hn);
            } else {
                return ('warning_no_such_hostname', $hn);
            }
        }
        while (my $ai = shift @aires) {
            debug(1, "found for hostname $hn\n");
            my $ip;
            if ($ai->{family} == AF_INET) {
                my ( $port, $ipaddr ) = unpack_sockaddr_in( $ai->{addr} );
                $ip = inet_ntoa($ipaddr);
            } else {
                my ( $port, $ipaddr ) = unpack_sockaddr_in6( $ai->{addr} );
                $ip = ipv6_n2x($ipaddr);
            }
            debug(1, "ipaddr=", $ip, "\n");
            # see if reverse resolution works
            my ($err, $hn2, $service) = getnameinfo($ai->{addr});
            if (!$err) {
                push @hostip, [$hn2, $ip];
                if (lc($hn) eq lc($hn2)) {
                    $found = 1;
                    last;
                }
            }
        }
        if (!$found) {
            system("/usr/bin/host -t CNAME $hn 2>&1 1> /dev/null");
            if ($? == 0){
                $found = 1;
            }
        }
    } elsif (eval {require Socket6; 1}) {
        debug(1, "Socket6\n");
        my @aires = getaddrinfo($hn, "ldap", AF_UNSPEC, SOCK_STREAM);
        if (scalar(@aires) < 5) {
            if ($res) {
                return $res->getText('warning_no_such_hostname', $hn);
            } else {
                return ('warning_no_such_hostname', $hn);
            }
        }
        my $ailen = scalar(@aires);
        while ($ailen >= 5) {
            debug(1, "found for hostname $hn\n");
            my $family = shift @aires;
            my $socktype = shift @aires;
            my $proto = shift @aires;
            my $saddr = shift @aires;
            my $canonname = shift @aires;
            $ailen = scalar(@aires);
            my $ip;
            if ($family == AF_INET) {
                my ($port, $ipaddr) = unpack_sockaddr_in($saddr);
                $ip = inet_ntoa($ipaddr);
            } else {
                my ($port, $ipaddr) = unpack_sockaddr_in6($saddr);
                $ip = ipv6_n2x($ipaddr);
            }
            debug(1, "ipaddr=", $ip, "\n");
            # see if reverse resolution works
            my ($hn2, $service) = getnameinfo($saddr);
            if ($hn2) {
                push @hostip, [$hn2, $ip];
                if (lc($hn) eq lc($hn2)) {
                    $found = 1;
                }
            }
        }
    } else {
        debug(1, "gethostbyname ...\n");
        # see if we can resolve the hostname
        my ($name, $aliases, $addrtype, $length, @addrs) = gethostbyname($hn);
        if (!$name) {
            if ($res) {
                return $res->getText('warning_no_such_hostname', $hn);
            } else {
                return ('warning_no_such_hostname', $hn);
            }
        }
        debug(1, "found for hostname $hn: name=$name\n");
        debug(1, "aliases=$aliases\n");
        debug(1, "addrtype=$addrtype\n");
         # see if reverse resolution works
        foreach my $ii (@addrs) {
            my $hn2 = gethostbyaddr($ii, $addrtype);
            my $ip = join('.', unpack('C4', $ii));
            debug(1, "\thost=$hn2 ip=$ip\n");
            push @hostip, [$hn2, $ip];
            if (lc($hn) eq lc($hn2)) {
                $found = 1;
                last;
            } 
        } 
    }

    if (!$found) {
        if ($res) {
            my $retstr = "";
            $retstr = $res->getText('warning_reverse_resolve', $hn, $hn);
            for my $ii (@hostip) {
                $retstr .= $res->getText('warning_reverse_resolve_sub', $ii->[1], $ii->[0]);
            }
            return $retstr;
        } else {
            my @reterrs = ();
            push @reterrs, [ 'warning_reverse_resolve', $hn, $hn ];
            for my $ii (@hostip) {
                push @reterrs, [ 'warning_reverse_resolve_sub', $ii->[1], $ii->[0] ];
            }
            return @reterrs;
        }
    }

    debug(1, "hostname $hn resolves correctly\n");
    if ($res) {
        return '';
    } else {
        return ();
    }
}

# delete the subtree starting from the passed entry
sub delete_all
{
    my ($conn, $bentry) = @_;
    my $sentry = $conn->search($bentry->{dn},
                               "subtree", "(objectclass=*)", 0, ("dn"));
    my @mystack = ();
    while ($sentry) {
        push @mystack, $sentry->getDN();
        $sentry = $conn->nextEntry();
    }
    # reverse order
    my $dn = pop @mystack;
    while ($dn) {
        $conn->delete($dn);
        my $rc = $conn->getErrorCode();
        if ( $rc != 0 ) {
            debug(1, "ERROR: unable to delete entry $dn, error code: $rc:" . $conn->getErrorString() . "\n");
            return 1;
        }
        $dn = pop @mystack;
    }
    return 0;
}

# if the entry does not exist on the server, add the entry.
# otherwise, do nothing
# you can use this as the callback to getMappedEntries, so
# that for each entry in the ldif file being processed, you
# can call this subroutine to add or update the entry
# use like this:
# getMappedEntries($mapper, \@ldiffiles, \&check_and_add_entry,
#                  [$conn, $fresh, $verbose]);
# where $conn is a perldap Conn
# $fresh if true will update the entry if it exists
# $verbose prints out more info
sub check_and_add_entry
{
    my ($context, $aentry, $errs) = @_;
    my $conn = $context->[0];
    my $fresh = $context->[1];
    my $verbose = $context->[2];
    my @ctypes = $aentry->getValues("changetype");
    my $sentry = $conn->search($aentry->{dn}, "base", "(objectclass=*)", 0, ("*", "aci"));
    if ($sentry) {
        debug(3, "check_and_add_entry: Found entry " . $sentry->getDN() . "\n");
        if ( (! @ctypes) or ("add" eq lc($ctypes[0])) ) { # entry exists, and this is not a modify op
                                                      # or add is explicitely specified
            debug(3, "check_and_add_entry: skipping entry " . $sentry->getDN() . "\n");
            return 1; # ignore - return success
        }
    } else {
        debug(3, "check_and_add_entry: Entry not found " . $aentry->{dn} .
              " error " . $conn->getErrorString() . "\n");
        if (@ctypes and !("add" eq lc($ctypes[0]))) { # uh oh - attempt to del/mod an entry that doesn't exist
            debug(3, "check_and_add_entry: attepting to @ctypes the entry " . $aentry->{dn} .
                  " that does not exist\n");
            return 1; # ignore - return success
        }
    }
    do
    {
        my @addtypes; # list of attr types for mod add
        my @reptypes; # list of attr types for mod replace
        my @deltypes; # list of attr types for mod delete
        my $OP_NONE = 0;
        my $OP_ADD = 1;
        my $OP_MOD = 2;
        my $OP_DEL = 3;
        # $op stores either of the above $OP_ values
        my $op = $OP_NONE;
        if ( (0 > $#ctypes) or ("add" eq lc($ctypes[0])) )    # aentry: complete entry
        {
            $op = $OP_ADD; # just add the entry
        }
        else    # aentry: modify format
        {
            if ( $sentry )
            {
                if ( "delete" eq lc($ctypes[0]) )
                {
                    $op = $OP_DEL;
                }
                else
                {
                    @addtypes = $aentry->getValues("add");
                    @reptypes = $aentry->getValues("replace");
                    @deltypes = $aentry->getValues("delete");
                    $op = $OP_MOD;
                }
            }
            else
            {
                $op = $OP_NONE;
            }
        }

        if ( $OP_ADD == $op )
        {
            if ("add" eq lc($ctypes[0])) {
                # remove the changetype: add from the entry
                $aentry->remove('changetype');
            }
            $conn->add($aentry);
            my $rc = $conn->getErrorCode();
            if ( $rc != 0 )
            {
                my $string = $conn->getErrorString();
                push @{$errs}, 'error_adding_entry', $aentry->{dn}, $string;
                debug(1, "ERROR: adding an entry $aentry->{dn} failed, error: $string\n");
                $aentry->printLDIF();
                $conn->close();
                return 0;
            }
            debug(1, "Entry $aentry->{dn} is added\n");
        }
        elsif ( $OP_DEL == $op )
        {
            my $rc = delete_all($conn, $sentry);
            if ( 0 != $rc )
            {
                push @{$errs}, 'error_deleteall_entries', $sentry->{dn}, $conn->getErrorString();
                debug(1, "Error deleting $sentry->{dn}\n");
                return 0;
            }
            debug(1, "Entry $aentry->{dn} is deleted\n");
            $sentry = undef;
        }
        elsif ( 0 < $op )    # modify op
        {
            my $attr;
            my @errsToIgnore;
            if (@addtypes) {
                push @errsToIgnore, LDAP_TYPE_OR_VALUE_EXISTS;
            }                
            foreach $attr ( @addtypes )
            {
                foreach my $val ($aentry->getValues($attr))
                {
                    debug(3, "Adding attr=$attr value=$val to entry $aentry->{dn}\n");
                    $sentry->addValue( $attr, $val );
                }
            }
            foreach $attr ( @reptypes )
            {
                my @vals = $aentry->getValues($attr);
                debug(3, "Replacing attr=$attr values=" . $aentry->getValues($attr) . " to entry $aentry->{dn}\n");
                $sentry->setValues($attr, @vals);
            }
            if (@deltypes) {
                push @errsToIgnore, LDAP_NO_SUCH_ATTRIBUTE;
            }
            foreach $attr ( @deltypes )
            {
                # removeValue takes a single value only
                if (!$aentry->size($attr))
                {
                    debug(3, "Deleting attr=$attr from entry $aentry->{dn}\n");
                    $sentry->remove($attr); # just delete the attribute
                }
                else
                {
                    debug(3, "Deleting attr=$attr values=" . $aentry->getValues($attr) . " from entry $aentry->{dn}\n");
                    foreach my $val ($aentry->getValues($attr))
                    {
                        $sentry->removeValue($attr, $val);
                    }
                }
            }
            $conn->update($sentry);
            my $rc = $conn->getErrorCode();
            if ( $rc != 0 )
            {
                my $string = $conn->getErrorString();
                debug(1, "ERROR: updating an entry $sentry->{dn} failed, error: $string\n");
                if (grep /^$rc$/, @errsToIgnore) {
                    debug(1, "Ignoring error $rc returned by adding @addtypes deleting @deltypes\n");
                } else {
                    push @{$errs}, 'error_updating_entry', $sentry->{dn}, $string;
                    $aentry->printLDIF();
                    $conn->close();
                    return 0;
                }
            }
        }
        if ( $sentry )
        {
            $sentry = $conn->nextEntry();    # supposed to have no more entries
        }
    } until ( !$sentry );
out:
    return 1;
}

# the default callback used with getMappedEntries
# just adds the given entry to the given list
sub cbaddent {
    my $list = shift;
    my $ent = shift;
    push @{$list}, $ent;
    return 1;
}

# given a mapper and a list of LDIF files, produce a list of
# perldap Entry objects which have had their tokens subst-ed
# with values from the mapper
# An optional callback can be supplied.  Each entry will be
# given to this callback.  The callback should return a list
# of localizable errors.  If no callback is supplied, the
# entries will be returned in a list.
# Arguments:
#  mapper - a hash ref - the keys are the tokens to replace
#           and the values are the replacements
#  ldiffiles - an array ref - the list of LDIF files to
#           operate on
#  errs -   an array ref - this is filled in with the
#           errors encountered in processing - this is
#           suitable for passing to setup->msg or
#           Resource->getText
#  callback (optional) - a code ref - a ref to a subroutine
#           that will be called with each entry - see below
#  context (optional) - this will be passed as the first
#           argument to your given callback - see below
# Callback:
#  The callback sub will be called for each entry after
#  the entry has been converted.  The callback will be
#  called with the given context as the first argument
#  and the Mozilla::LDAP::Entry as the second argument,
#  and an errs array ref as the third argument.  The
#  callback should return true to continue processing,
#  or false if a fatal error was encountered that should
#  abort processing of any further.
# Errors:
#  This function should return an array of errors in the
#  format described below, for use with Resource::getText()
#  or Setup::msg()
# Return:
#  The return value is a list of entries.
# Example usage:
#  sub handle_entries {
#    my $context = shift;
#    my $entry = shift;
#    my $errs = shift;
#    .... do something with entry ....
#    .... if $context is Mozilla::LDAP::Conn, $conn->add($entry); ...
#    .... report errors ....
#    if ($fatalerror) {
#      push @{$errs}, 'error_token', arg1, arg2, ...;
#      return 0;
#    } else {
#      return 1;
#    }
#  }
#  $mapper = {foo => 'bar', baz => 'biff'};
#  @ldiffiles = ('foo.ldif', 'bar.ldif', ..., 'biff.ldif');
#  $conn = new Mozilla::LDAP::Conn(...);
#  my @errs;
#  @entries = getMappedEntries($mapper, \@ldiffiles, \@errs, \&handle_entries, $conn);
#  Note that this will return 0 entries since a callback was used.
#  The simpler example is this:
#  @entries = getMappedEntries($mapper, \@ldiffiles, \@errs);
#  
sub getMappedEntries {
    my $mapper = shift;
    my $ldiffiles = shift;
    my $errs = shift;
    my $callback = shift || \&cbaddent; # default - just add entry to @entries
    my @entries = ();
    my $context = shift || \@entries;
    my $error;

    if (!ref($ldiffiles)) {
        $ldiffiles = [ $ldiffiles ];
    }

    foreach my $ldiffile (@{$ldiffiles}) {
        if (!open(MYLDIF, "< $ldiffile")) {
            push @{$errs}, "error_opening_ldiftmpl", $ldiffile, $!;
            return 0;
        }
        my $in = new Mozilla::LDAP::LDIF(*MYLDIF);
        debug(1, "Processing $ldiffile ...\n");
        ENTRY: while (my $entry = Mozilla::LDAP::LDIF::readOneEntry($in)) {
            # first, fix the DN
            my $dn = $entry->getDN();
            my $origdn = $dn;
            while ( $dn =~ /%([\w_-]+)%/ ) {
                if (exists($mapper->{$1})) {
                    $dn =~ s{%([\w_-]+)%}{$mapper->{$1}}ge;
                } else {
                    push @{$errs}, 'error_mapping_token_ldiftmpl', $dn, $ldiffile, $1;
                    $error = 1;
                    last ENTRY;
                }
            }
            $entry->setDN($dn);
            # next, fix all of the values in all of the attributes
            foreach my $attr (keys %{$entry}) {
                my @newvalues = ();
                foreach my $value ($entry->getValues($attr)) {
                    # Need to repeat to handle nested subst
                    my $origvalue = $value;
                    while ( $value =~ /%([\w_-]+)%/ ) {
                        if (exists($mapper->{$1})) {
                            $value =~ s{%([\w_-]+)%}{$mapper->{$1}}ge;
                        } else {
                            push @{$errs}, 'error_mapping_token_ldiftmpl', $dn, $ldiffile, $1;
                            debug(1, "ERROR: \"$origvalue\" mapped to \"$value\".\n");
                            $error = 1;
                            last ENTRY;
                        }
                    }
                    push @newvalues, $value;
                }
                $entry->setValues( $attr, @newvalues );
            }

            if (!&{$callback}($context, $entry, $errs)) {
                debug(1, "ERROR: There was an error processing entry ". $entry->getDN(). "\n");
                debug(1, "Cannot continue processing entries.\n");
                $error = 1;
                last ENTRY;
            }                

        }
        close(MYLDIF);
        last if ($error); # do not process any more ldiffiles if an error occurred
    }

    return @entries;
}

# you should only use this function if you know for sure
# that the suffix and backend do not already exist
# use addSuffix instead
sub newSuffixAndBackend {
    my $context = shift;
    my $suffix = shift;
    my $bename = shift;
    my $nsuffix = normalizeDN($suffix);
    my @errs;

    my $dn = "cn=$bename, cn=ldbm database, cn=plugins, cn=config";
    my $entry = new Mozilla::LDAP::Entry();
    $entry->setDN($dn);
    $entry->setValues('objectclass', 'top', 'extensibleObject', 'nsBackendInstance');
    $entry->setValues('cn', $bename);
    $entry->setValues('nsslapd-suffix', $nsuffix);
    $context->add($entry);
    my $rc = $context->getErrorCode();
    if ($rc) {
        return ('error_creating_suffix_backend', $suffix, $bename, $context->getErrorString());
    }

    $entry = new Mozilla::LDAP::Entry();
    $dn = "cn=\"$nsuffix\", cn=mapping tree, cn=config";
    $entry->setDN($dn);
    $entry->setValues('objectclass', 'top', 'extensibleObject', 'nsMappingTree');
    $entry->setValues('cn', "\"$nsuffix\"");
    $entry->setValues('nsslapd-state', 'backend');
    $entry->setValues('nsslapd-backend', $bename);
    $context->add($entry);
    $rc = $context->getErrorCode();
    if ($rc) {
        return ('error_creating_suffix', $suffix, $context->getErrorString());
    }

    return ();
}

sub findbecb {
    my $entry = shift;
    my $attrs = shift;
    return $entry->hasValue('objectclass', $attrs->[0], 1) &&
        $entry->hasValue('cn', $attrs->[1], 1);
}

sub findBackend {
    my $context = shift;
    my $bename = shift;
    my $ent;
    if (ref($context) eq 'Mozilla::LDAP::Conn') {
        $ent = $context->search("cn=ldbm database,cn=plugins,cn=config", "one",
                                "(&(objectclass=nsBackendInstance)(cn=$bename)")
    } else {
        $ent = $context->search("cn=ldbm database,cn=plugins,cn=config", "one",
                                \&findbecb, ['nsBackendInstance', $bename])
    }
}

sub findsuffixcb {
    my $entry = shift;
    my $attrs = shift;
    return $entry->hasValue('cn', $attrs->[0], 1) ||
        $entry->hasValue('cn', $attrs->[1], 1);
}

sub findSuffix {
    my $context = shift;
    my $suffix = shift;
    my $nsuffix = normalizeDN($suffix);
    my $ent;
    if (ref($context) eq 'Mozilla::LDAP::Conn') {
        $ent = $context->search("cn=mapping tree,cn=config", "one",
                                "(|(cn=\"$suffix\")(cn=\"$nsuffix\"))");
    } else {
        $ent = $context->search("cn=mapping tree,cn=config", "one",
                                \&findsuffixcb, ["\"$suffix\"", "\"$nsuffix\""])
    }
}

sub getUniqueBackendName {
    my $context = shift;
    my $bename = "backend";
    my $index = 0;
    my $ent = findBackend($context, ($bename . $index));
    while ($ent) {
        ++$index;
        $ent = findBackend($context, ($bename . $index));
    }

    return $bename.$index;
}

sub addSuffix {
    my $context = shift; # Conn
    my $suffix = shift;
    my $bename = shift; # optional
    my $ent;

    if ($bename && ($ent = findBackend($context, $bename))) {
        return ('backend_already_exists', $bename, $ent->getDN());
    }

    if ($ent = findSuffix($context, $suffix)) {
        return ('suffix_already_exists', $suffix, $ent->getDN());
    }

    if (!$bename) {
        $bename = getUniqueBackendName($context);
    }

    my @errs = newSuffixAndBackend($context, $suffix, $bename);

    return @errs;
}

# process map table
# [map table sample]
# fqdn =    FullMachineName
# hostname =    `use Sys::Hostname; $returnvalue = hostname();`
# ds_console_jar ="%normbrand%-ds-%ds_version%.jar"
#
# * If the right-hand value is in ` (backquote), the value is eval'ed by perl.
#   The output should be stored in $returnvalue to pass to the internal hash.
# * If the right-hand value is in " (doublequote), the value is passed as is.
# * If the right-hand value is not in any quote, the value should be found
#   in either of the setup inf file (static) or the install inf file (dynamic).
# * Variables surrounded by @ (e.g., @admin_confdir@) are replaced with the 
#   system path at the compile time.
# * The right-hand value can contain variables surrounded by % (e.g., %asid%)
#   which refers the right-hand value (key) of this map file.
# The %token% tokens are replaced in getMappedEntries
sub process_maptbl
{
    my ($mapper, $errs, @infdata) = @_;
    my @deferredkeys = ();

    if (defined($mapper->{""})) {
        $mapper = $mapper->{""}; # side effect of Inf with no sections
    }

    KEY: foreach my $key (keys %{$mapper})
    {
        my $value = $mapper->{$key};
        if ($value =~ /^\"/)
        {
            $value =~ tr/\"//d; # value is a regular double quoted string - remove quotes
            $mapper->{$key} = $value;
        }
        elsif ($value =~ /^\`/)
        {
            push @deferredkeys, $key; # process these last
        }
        else
        {
            # get the value from one of the Inf passed in
            # they $value could be pure Key or Key:"default_value"
            my ($key_value, $default_value) = split(/:/, $value, 2);
            my $infsection;
            foreach my $thisinf (@infdata)
            {
                foreach my $section0 (keys %{$thisinf})
                {
                    $infsection = $thisinf->{$section0};
                    next if (!ref($infsection));
                    if (defined($infsection->{$key_value}))
                    {
                        $mapper->{$key} = $infsection->{$key_value};
                        next KEY;
                    }
                }
            }
            if ($default_value ne "")
            {
                $default_value =~ tr/\"//d; # default_value is a regular double quoted string - remove quotes
                $mapper->{$key} = $default_value;
            }
            else
            {
                push @{$errs}, ['no_mapvalue_for_key', $value, $key];
                return {};
            }
        }
    }

    # we have to process the perl expressions to eval last, because those
    # expressions may use mappings defined elsewhere in the file, and we are not
    # guaranteed of the order in which hash keys are enumerated
    foreach my $key (@deferredkeys) {
        my $value = $mapper->{$key};
        $value =~ tr/\`//d; # value is a perl expression to eval
        my $returnvalue; # set in eval expression
        eval $value;
        $mapper->{$key} = $returnvalue; # perl expression sets $returnvalue
    }

    return $mapper;
}

# given a string, escape the characters in the string
# so that it can be safely passed to the shell via
# the system() call or `` backticks
sub shellEscape {
    my $val = shift;
    # first, escape the double quotes and slashes
    $val =~ s/([\\"])/\\$1/g; # " font lock fun
    # next, escape the rest of the special chars
    my $special = '!$\' @#%^&*()|[\]{};:<>?/`';
    $val =~ s/([$special])/\\$1/g;

    return $val;
}

# given a string, escape the special characters in the string.
# the characters are defined in RFC 4514.
# special = escaped / SPACE / SHARP / EQUALS
# escaped = DQUOTE / PLUS / COMMA / SEMI / LANGLE / RANGLE
# hex string "# HEX HEX" is unlikely appearing in the installation.
# thus, it won't be supported for now.
my %dnspecial = (
    '"'  => '\\"',  # '\\22'
    '\+' => '\\+',  # '\\2B'
    ','  => '\\,',  # '\\2C'
    ';'  => '\\;',  # '\\3B'
    '<'  => '\\<',  # '\\3C'
    '>'  => '\\>',  # '\\3E'
    '='  => '\\='   # '\\3D'
);

sub dnEscape {
    my $val = shift;
    # first, remove spaces surrounding ',' and leading/trailing spaces
    $val =~ s/^\s*//;
    $val =~ s/\s*$//;
    $val =~ s/\s*,\s*/,/g;
    # next, replace the special characters
    foreach my $idx (keys %dnspecial) {
        $val =~ s/$idx/$dnspecial{$idx}/g;
    }
    $val =~ s/\s*,\s*/,/g;

    return $val;
}

sub getHashedPassword {
    my $pwd = shift;
    my $alg = shift;

    if ($pwd =~ /^\{\w+\}.+/) {
        return $pwd; # already hashed
    }

    my $cmd = "/usr/bin/pwdhash";
    if ($alg) {
        $cmd .= " -s $alg";
    }
    $cmd .= " -- " . shellEscape($pwd);
    my $hashedpwd = `$cmd`;
    chomp($hashedpwd);

    return $hashedpwd;
}

# this creates an Inf suitable for passing to createDSInstance
# except that it has a bogus suffix
sub createInfFromConfig {
    my $configdir = shift;
    my $inst = shift;
    my $errs = shift;
    my $fname = "$configdir/dse.ldif";
    my $id;
    ($id = $inst) =~ s/^slapd-//;
    if (! -f $fname || ! -r $fname) {
        push @{$errs}, "error_opening_dseldif", $fname, $!;
        return 0;
    }
    my $conn = new FileConn($fname, 1);
    if (!$conn) {
        push @{$errs}, "error_opening_dseldif", $fname, $!;
        return 0;
    }

    my $ent = $conn->search("cn=config", "base", "(objectclass=*)");
    if (!$ent) {
        push @{$errs}, "error_opening_dseldif", $fname, $!;
        $conn->close();
        return 0;
    }

    my $inf = new Inf();
    $inf->{General}->{FullMachineName} = $ent->getValues('nsslapd-localhost');
    $inf->{General}->{SuiteSpotUserID} = $ent->getValues('nsslapd-localuser');
    $inf->{slapd}->{RootDN} = $ent->getValues('nsslapd-rootdn');
    $inf->{slapd}->{RootDNPwd} = $ent->getValues('nsslapd-rootpw');
    $inf->{slapd}->{ServerPort} = $ent->getValues('nsslapd-port');
    $inf->{slapd}->{ServerIdentifier} = $id;

    my $suffix = "";
    $ent = $conn->search("cn=ldbm database,cn=plugins,cn=config",
                         "one", "(objectclass=*)");
    if (!$ent) {
        push @{$errs}, "error_opening_dseldif", $fname, $!;
        $conn->close();
        return 0;
    }
    # use the userRoot suffix if available
    while ($ent) {
        if ($ent->getValues('nsslapd-suffix')) {
            $suffix = $ent->getValues('nsslapd-suffix');
        }
        last if ($ent->hasValue('cn', 'userRoot', 1));
        $ent = $conn->nextEntry();
    }
    if ( "" eq "$suffix" )
    {
        push @{$errs}, "error_opening_dseldif", $fname, $!;
        $conn->close();
        return 0;
    }

    # we also need the instance dir
    $ent = $conn->search("cn=config", "base", "(objectclass=*)");
    if (!$ent) {
        push @{$errs}, "error_opening_dseldif", $fname, $!;
        $conn->close();
        return 0;
    }
    my $inst_dir = $ent->getValue('nsslapd-instancedir');

    $conn->close();

    if ($inst_dir) {
        $inf->{slapd}->{inst_dir} = $inst_dir;
    }
    $inf->{slapd}->{Suffix} = $suffix;

    return $inf;
}

# like File::Path mkpath, except we can set the owner and perm
# of each new path and parent path created
sub makePaths {
    my ($path, $mode, $user, $group) = @_;
    my $uid = getpwnam $user;
    my $gid = -1; # default to leave it alone
    my $mode_string = "";

    if ($group) {
        $gid = getgrnam $group;
    }
    my @dirnames = ($path);
    my $parent = $path;
    for ($parent = dirname($parent);
         $parent and ($parent ne "/");
         $parent = dirname($parent)) {
        unshift @dirnames, $parent;
    }
    for my $dir (@dirnames) {
        next if (-d $dir);
        $! = 0; # clear
        mkdir $dir, $mode;
        if ($!) {
            return ('error_creating_directory', $dir, $!);
        }
        chown $uid, $gid, $dir;
        if ($!) {
            return ('error_chowning_directory', $dir, $!);
        }
        chmod $mode, $dir;
        $mode_string = sprintf "%lo", $mode;
        debug(1, "makePaths: created directory $dir mode $mode_string user $user group $group\n");
        debug(2, "\t" . `ls -ld $dir`);
    }

    return ();
}

# remove_tree($centry, $key, $instname, [$isparent, [$dontremove]])
#     $centry: entry to look for the path to be removed
#     $key: key to look for the path in the entry
#     $instname: instance name "slapd-<ID>" to check the path
#     $isparent: specify 1 to remove from the parent dir
#     $dontremove: pattern not to be removed (e.g., ".db$")
sub remove_tree
{
    my $centry = shift;
    my $key = shift;
    my $instname = shift;
    my $isparent = shift;
    my $dontremove = shift;
    my @errs = (); # a list of array refs - each array ref is suitable for passing to Resource::getText

    foreach my $path ( @{$centry->{$key}} )
    {
        my $rmdir = "";
        my $rc = 0;
        if ( 1 == $isparent )
        {
            $rmdir = dirname($path);
        }
        else
        {
            $rmdir = $path;
        }
        if ( -d $rmdir && $rmdir =~ /$instname/ )
        {
            if ( "" eq "$dontremove" )
            {
                $rc = rmtree($rmdir);
                if ( 0 == $rc )
                {
                    push @errs, [ 'error_removing_path', $rmdir, $! ];
                    debug(1, "Warning: $rmdir was not removed.  Error: $!\n");
                }
            }
            else
            {
                # Skip the dontremove files
                $rc = opendir(DIR, $rmdir);
                if ($rc)
                {
                    while (defined(my $file = readdir(DIR)))
                    {
                        next if ( "$file" =~ /$dontremove/ );
                        next if ( "$file" eq "." );
                        next if ( "$file" eq ".." );
                        my $rmfile = $rmdir . "/" . $file;
                        my $rc0 = rmtree($rmfile);
                        if ( 0 == $rc0 )
                        {
                            push @errs, [ 'error_removing_path', $rmfile, $! ];
                            debug(1, "Warning: $rmfile was not removed.  Error: $!\n");
                        }
                    }
                    closedir(DIR);
                }
                my $newrmdir = $rmdir . ".removed";
                my $rc1 = 1;
                if ( -d $newrmdir )
                {
                    $rc1 = rmtree($newrmdir);
                    if ( 0 == $rc1 )
                    {
                        push @errs, [ 'error_removing_path', $newrmdir, $! ];
                        debug(1, "Warning: $newrmdir was not removed.  Error: $!\n");
                    }
                }
                if ( 0 < $rc1 )
                {
                    rename($rmdir, $newrmdir);
                }
            }
        }
    }

    return @errs; # a list of array refs - if (!@errs) then success
}

sub remove_pidfile
{
    my ($type, $serv_id, $instdir, $instname, $run_dir, $product_name) = @_;
    my $pidfile;

    # Construct the pidfile name as follows:
    #     PIDFILE=$RUN_DIR/$PRODUCT_NAME-$SERV_ID.pid
    #     STARTPIDFILE=$RUN_DIR/$PRODUCT_NAME-$SERV_ID.startpid
    if ($type eq "PIDFILE") {
        $pidfile = $run_dir . "/" . $product_name . "-" . $serv_id . ".pid";
    } elsif ($type eq "STARTPIDFILE") {
        $pidfile = $run_dir . "/" . $product_name . "-" . $serv_id . ".startpid";
    }

    if ( -e $pidfile && $pidfile =~ /$instname/ )
    {
        unlink($pidfile);
    }
}

sub serverIsRunning
{
    my ($run_dir, $inst) = @_;
    my $pidfile = $run_dir . "/" . $inst . ".pid";
    if ( -e $pidfile ) {
        if (!open(PIDFILE, $pidfile)) {
            debug(3, "Could not open pidfile $pidfile - $! - assume server is not running\n");
            return 0; # could not open pid file - assume server is not running
        }
        my $pid = <PIDFILE>;
        chomp($pid);
        close(PIDFILE);
        if (!$pid) {
            debug(3, "Bogus pid $pid found in pidfile $pidfile - assume server is not running\n");
            return 0; # could not open pid file - assume server is not running
        }
        if (kill(0, $pid)) {
            debug(3, "pid $pid from file $pidfile is running\n");
            return 1; # server is running
        }
        debug(3, "pid $pid from file $pidfile is not running - could not kill 0 - $!\n");
    } else {
        debug(3, "No such file pidfile $pidfile - $! - assume server is not running\n");
    }

    return 0; # no pid file - assume not running
}

sub libpath_add {
    my $libpath = shift;

    if ($libpath) {
        if ($ENV{'LD_LIBRARY_PATH'}) {
            $ENV{'LD_LIBRARY_PATH'} = "$ENV{'LD_LIBRARY_PATH'}:$libpath";
        } else {
            $ENV{'LD_LIBRARY_PATH'} = "$libpath";
        }
    }
}

# 
# get_info()
#
# Grab all the config settings we need from the dse.ldif
#
sub get_info {
    my %info = ();
    my $dir = shift;
    $info{host} = shift;
    $info{port} = shift; 
    $info{rootdn} = shift;
    my $dse_file = "$dir/dse.ldif";
    my $foundcfg = "no";
    my $value;
    my $entry;
    my $ldif;
    
    #
    # Are we using openLDAP or Mozilla?
    #
    my $toollib = `ldapsearch -V 2>&1`;
    if ($toollib =~ /OpenLDAP/) { 
        $info{openldap} = "yes";
        $info{nofold} = "-o ldif-wrap=no";
    } else {
        $info{openldap} = "no";
        $info{nofold} = "-T";
    }
    
    #
    # Open dse.ldif and grab the cn=config entry
    #
    open(DSE, "$dse_file") || die "Failed to open config file $dse_file $!\n";
    $ldif = new Mozilla::LDAP::LDIF(*DSE);
    while($entry = readOneEntry $ldif){
        if($entry->getDN() eq "cn=config"){
            $foundcfg = "yes";
            last;
        }
    }
    if($foundcfg eq "no"){
        print (STDERR "Failed to find \"cn=config\" entry from $dse_file\n");
        close (DSE);
        exit 1;
    }

    #
    # Get missing info
    #
    if($info{host} eq ""){
        $info{host} = $entry->getValues("nsslapd-localhost");
    }
    if($info{port} eq ""){
        $info{port} = $entry->getValues("nsslapd-port") || "389";
    }
    if($info{rootdn} eq ""){
        $info{rootdn} = $entry->getValues("nsslapd-rootdn");
    }
    
    # 
    # Get SSL and LDAPI settings
    #
    $info{certdir} = $entry->getValues("nsslapd-certdir");
    if($info{openldap} eq "yes"){
        $ENV{LDAPTLS_CACERTDIR}=$info{certdir};
    }
    $info{security} = $entry->getValues("nsslapd-security");
    $info{secure_port} = $entry->getValues("nsslapd-securePort") || "636";
    $info{ldapi} = $entry->getValues("nsslapd-ldapilisten");
    $info{autobind} = $entry->getValues("nsslapd-ldapiautobind");
    $value = $entry->getValues("nsslapd-ldapifilepath");
    if ($value){
        $value =~ s/\//%2f/g;
        $info{ldapiURL} = "ldapi://" . $value;
    }

    while($entry = readOneEntry $ldif){
        if($entry->getDN() eq "cn=encryption,cn=config"){
            $foundcfg = "yes";
            last;
        }
    }
    if($foundcfg eq "yes" && $entry){
        $info{cacertfile} = $entry->getValues("CACertExtractFile");
        if ($info{cacertfile}) {
            $ENV{LDAPTLS_CACERT}=$info{cacertfile};
        }
    }

    close (DSE);
    return %info;
}

#
# return the normalized server id and the server config dir (contains dse.ldif)
#
sub get_server_id {
    my $servid = shift;
    my $dir = shift;
    my $instance_count = 0;
    my $first = "yes";
    my $instances = "<none>";
    my $name;
    my $inst;
    my $file;
    my @extra = ();
    my $extradir = "";

    if (getLogin ne 'root') {
        $extradir = "$ENV{HOME}/.dirsrv";
        if (-d $extradir) {
            opendir(EXTRADIR, $extradir);
            @extra = map {$_ = "$extradir/$_"} readdir(EXTRADIR);
            closedir(EXTRADIR);
        }
    }

    if (defined $ENV{INITCONFIGDIR}) {
        $dir = $ENV{INITCONFIGDIR};
        @extra = (); # only use what was provided
        $extradir = "";
    }

    # normalize the given servid
    if (!$servid) {
        # not given
    } elsif ($servid =~ /^dirsrv-/){
        # strip off "dirsrv-"
        $servid =~ s/^dirsrv-//;
    } elsif ($servid =~ /^slapd-/){
        # strip off "slapd-"
        $servid =~ s/^slapd-//;
    } # else assume already normalized

    opendir(DIR, "$dir");
    my @files = map {$_ = "$dir/$_"} readdir(DIR);
    closedir(DIR);
    push @files, @extra;
    my $found = 0;
    foreach $file (@files){
        next if(! -r $file); # skip unreadable files
        # skip admin server
        if($file =~ m,/dirsrv-([^/]+)$, && $file !~ m,/dirsrv-admin$,){
            $name = $file;
            $inst = $1;
            $instance_count++;
            if ($servid && ($servid eq $inst)) {
                $found = 1;
                last;
            }
            if($first eq "yes"){
                $instances=$inst;
                $first = "no";
            } else {
                $instances=$instances . ", $inst";
            }
        }
    }

    if ($servid && !$found) { # if we got here, did not find given serverid
        print (STDERR "Invalid server identifer: $servid\n");
        print (STDERR "Available instances in $dir $extradir: $instances\n");
        exit (1);
    }
        
    if ($instance_count == 0){
        print "No instances found in $dir\n";
        exit (1);
    }
    
    if (!$servid && $instance_count > 1){
        print "You must supply a valid server instance identifier.  Use -Z to specify instance name\n";
        print "Available instances: $instances\n";
        exit (1);
    }
    unless ( -e "$name" ){
        print (STDERR "Invalid server identifer: $servid\n");
        print (STDERR "Available instances in $dir $extradir: $instances\n");
        exit (1);
    }

    # now grab the CONFIG_DIR from the file $name
    if (!open(INSTFILE, "$name")) {
        print (STDERR "Error: could not open $name: ");
        exit (1);
    }

    my $confdir;
    while (<INSTFILE>) {
        if (/^CONFIG_DIR=/) {
            s/^CONFIG_DIR=//;
            s/ ; export CONFIG_DIR//;
            $confdir = $_;
            chomp($confdir);
            last;
        }
    }
    close INSTFILE;

    if (!$confdir) {
        print (STDERR "Error: no CONFIG_DIR found in $name\n");
        exit (1);
    }
    
    return ($inst, $confdir);
}

#
# Get the root DN password from the file, or command line input
#
sub get_password_from_file {
    my $passwd = shift;
    my $passwdfile = shift;
    
    if ($passwdfile ne ""){
        # Open file and get the password
        unless (open (RPASS, $passwdfile)) {
            die "Error, cannot open password file $passwdfile\n";
        }
        $passwd = <RPASS>;
        chomp($passwd);
        close(RPASS);
    } elsif ($passwd eq "-"){
        # Read the password from terminal
        print "Bind Password: ";
        # Disable console echo
        system("/bin/stty -echo") if -t STDIN;
        # read the answer
        $passwd = <STDIN>;
        # Enable console echo
        system("/bin/stty echo") if -t STDIN;
        print "\n";
        chop($passwd); # trim trailing newline
    }
    
    return $passwd;
}

#
# Execute the ldapmodify
#
sub ldapmod {
    my $entry = shift;
    my %info = @_;
    my $file = "/tmp/DSUtil-$$.txt";
    my $protocol_error;
    my $result;
    my $rc;
    my $myrootdnpw = shellEscape($info{rootdnpw});
    
    # 
    # write the entry to file so we can grab the result code after running ldapmodify(-f)
    #
    if(!open (FILE, ">$file") ){
        print (STDERR "DSUtil::ldapmod() failed to create tmp file ($!)\n");
        return 1;
    } else {
        print (FILE "$entry\n");
        close (FILE);
    }

    if ($info{redirect} eq ""){
        $info{redirect} = "> /dev/null";
    }

    #
    # Check the protocol, and reset it if it's invalid
    #
    $result = check_protocol(%info);
    if($result == 1){
        $protocol_error = "yes";
        $info{protocol} = "";
    } elsif( $result == 2){
        unlink ($file);
        return 1;
    }

    #
    # Execute ldapmodify using the specified/most secure protocol
    #
    if (($info{security} eq "on" && $info{protocol} eq "") || ($info{security} eq "on" && $info{protocol} =~ m/STARTTLS/i) ){
        # 
        # STARTTLS
        #
        if($protocol_error eq "yes"){
            print "STARTTLS)\n";
        }
        if($info{openldap} eq "yes"){
            system "ldapmodify -x -ZZ -h $info{host} -p $info{port} -D \"$info{rootdn}\" -w $myrootdnpw $info{args} -f \"$file\" $info{redirect}";
        } else {
            system "ldapmodify -ZZZ -P \"$info{certdir}\" -h $info{host} -p $info{port} -D \"$info{rootdn}\" -w $myrootdnpw $info{args} -f \"$file\" $info{redirect}";
        }
    } elsif (($info{security} eq "on" && $info{protocol} eq "") || ($info{security} eq "on" && $info{protocol} =~ m/LDAPS/i) ){ 
        # 
        # LDAPS
        #
        if($protocol_error eq "yes"){
            print "LDAPS)\n";
        }
        if($info{openldap} eq "yes"){
            system "ldapmodify -x -H \"ldaps://$info{host}:$info{secure_port}\" -D \"$info{rootdn}\" -w $myrootdnpw $info{args} -f \"$file\" $info{redirect}";
        } else {
            system "ldapmodify -Z -P \"$info{certdir}\" -p $info{secure_port} -D \"$info{rootdn}\" -w $myrootdnpw $info{args} -f \"$file\" $info{redirect}";
        }
    } elsif (($info{openldap} eq "yes") && (($info{ldapi} eq "on" && $info{protocol} eq "") || ($info{ldapi} eq "on" && $info{protocol} =~ m/LDAPI/i)) ){  
        #
        # LDAPI
        #
        if ($< == 0 && $info{autobind} eq "on"){
            if($protocol_error eq "yes"){
                print "LDAPI/AUTOBIND)\n";
            }
            system "ldapmodify -H \"$info{ldapiURL}\" -Y EXTERNAL $info{args} -f \"$file\" > /dev/null 2>&1";
        } else {
            if($protocol_error eq "yes"){
                print "LDAPI)\n";
            }
            system "ldapmodify -x -H \"$info{ldapiURL}\" -D \"$info{rootdn}\" -w $myrootdnpw $info{args} -f \"$file\" $info{redirect}";
        }
    } else {
        # 
        # LDAP
        #
        if($protocol_error eq "yes"){
            print "LDAP)\n";
        }
        if($info{openldap} eq "yes"){
            system "ldapmodify -x -h $info{host} -p $info{port} -D \"$info{rootdn}\" -w $myrootdnpw $info{args} -f \"$file\" $info{redirect}";
        } else {
            system "ldapmodify -h $info{host} -p $info{port} -D \"$info{rootdn}\" -w $myrootdnpw $info{args} -f \"$file\" $info{redirect}";
        }
    }
    unlink ($file);
    if ($? != 0){
        my $retCode=$?>>8;
        return $retCode;
    }
    return 0;
}

#
# Build the ldapsearch
#
sub ldapsrch {
    my %info = @_;
    my $protocol_error;
    my $search;
    my $result;
    my $myrootdnpw = shellEscape($info{rootdnpw});
    
    $result = check_protocol(%info);
    if($result == 1){
        $protocol_error = "yes";
        $info{protocol} = "";
    } elsif( $result == 2){
        return "";
    }
    if (($info{security} eq "on" && $info{protocol} eq "") || ($info{security} eq "on" && $info{protocol} =~ m/STARTTLS/i) ){
        #
        # STARTTLS
        #
        if($protocol_error eq "yes"){
            print "STARTTLS)\n";
        }
        if($info{openldap} eq "yes"){
            $search = "ldapsearch -x -LLL -ZZ -p $info{port} -h $info{host} -D \"$info{rootdn}\" -w $myrootdnpw $info{nofold} " .
                      "$info{srch_args} -b \"$info{base}\" -s $info{scope} \"$info{filter}\" $info{attrs}";
        } else {
            $search = "ldapsearch -ZZZ -P \"$info{certdir}\" -p $info{port} -h $info{host} -D \"$info{rootdn}\" $info{nofold} " .
                      "-w $myrootdnpw $info{srch_args} -b \"$info{base}\" -s $info{scope} \"$info{filter}\" $info{attrs}";
        }  
    } elsif (($info{security} eq "on" && $info{protocol} eq "") || ($info{security} eq "on" && $info{protocol} =~ m/LDAPS/i) ){ 
        # 
        # LDAPS
        #
        if($protocol_error eq "yes"){
            print "LDAPS)\n";
        }
        if($info{openldap} eq "yes"){
            $search = "ldapsearch -x -LLL -H \"ldaps://$info{host}:$info{secure_port}\" -D \"$info{rootdn}\" $info{nofold} " .
                      "-w $myrootdnpw $info{srch_args} -b \"$info{base}\" -s $info{scope} \"$info{filter}\" $info{attrs}";
        } else {
            $search = "ldapsearch -Z -P \"$info{certdir}\" -p $info{secure_port} -h $info{host} -D \"$info{rootdn}\" $info{nofold} " .
                      "-w $myrootdnpw $info{srch_args} -b \"$info{base}\" -s $info{scope} \"$info{filter}\" $info{attrs}";
        } 
    } elsif (($info{openldap} eq "yes") && (($info{ldapi} eq "on" && $info{protocol} eq "") || ($info{ldapi} eq "on" && $info{protocol} =~ m/LDAPI/i)) ){  
        # 
        # LDAPI
        #
        if ($< == 0 && $info{autobind} eq "on"){
            $search = "ldapsearch  -LLL -H \"$info{ldapiURL}\" -Y EXTERNAL $info{nofold} " .
                  "$info{srch_args} -b \"$info{base}\" -s $info{scope} \"$info{filter}\" $info{attrs} 2>/dev/null";
        } else {
            $search = "ldapsearch -x -LLL -H \"$info{ldapiURL}\" -D \"$info{rootdn}\" -w $myrootdnpw $info{nofold} " .
                  "$info{srch_args} -b \"$info{base}\" -s $info{scope} \"$info{filter}\" $info{attrs}";
        }
    } else {
        # 
        # LDAP
        #
        if($protocol_error eq "yes"){
            print "LDAP)\n";
        }
        if($info{openldap} eq "yes"){
            $search = "ldapsearch -x -LLL -p $info{port} -h $info{host} -D \"$info{rootdn}\" -w $myrootdnpw $info{nofold} " .
                  "$info{srch_args} -b \"$info{base}\" -s $info{scope} \"$info{filter}\" $info{attrs}";
        } else {
            $search = "ldapsearch -p $info{port} -h $info{host} -D \"$info{rootdn}\" -w $myrootdnpw $info{nofold} " .
                  "$info{srch_args} -b \"$info{base}\" -s $info{scope} \"$info{filter}\" $info{attrs}";
        }
    }
    return $search;
}

#
# Execute the search
#
sub ldapsrch_ext {
    my %info = @_;
    my $protocol_error;
    my $result;
    my $txt;
    my $myrootdnpw = shellEscape($info{rootdnpw});
    
    $result = check_protocol(%info);
    if($result == 1){
        $protocol_error = "yes";
        $info{protocol} = "";
    } elsif($result == 2){
        return 1;
    }
    if (($info{security} eq "on" && $info{protocol} eq "") || ($info{security} eq "on" && $info{protocol} =~ m/STARTTLS/i) ){
        # 
        # STARTTLS
        #
        if($protocol_error eq "yes"){
            print "STARTTLS)\n";
        }
        if($info{openldap} eq "yes"){
            return `ldapsearch -x -LLL -ZZ -p $info{port} -h $info{host} -D \"$info{rootdn}\" -w $myrootdnpw $info{nofold} $info{srch_args} -b \"$info{base}\" -s $info{scope} \"$info{filter}\" $info{attrs} $info{redirect}`;
        } else {
            return `ldapsearch -ZZZ -P $info{certdir} -p $info{port} -h $info{host} -D \"$info{rootdn}\" -w $myrootdnpw $info{nofold} $info{srch_args} -b \"$info{base}\" -s $info{scope} \"$info{filter}\" $info{attrs} $info{redirect}`;
        }     
    } elsif (($info{security} eq "on" && $info{protocol} eq "") || ($info{security} eq "on" && $info{protocol} =~ m/LDAPS/i) ){ 
        # 
        # LDAPS
        #
        if($protocol_error eq "yes"){
            print "LDAPS)\n";
        }
        if($info{openldap} eq "yes"){
            return `ldapsearch -x -LLL -H ldaps://$info{host}:$info{secure_port} -D \"$info{rootdn}\" -w $myrootdnpw $info{nofold} $info{srch_args}  -b \"$info{base}\" -s $info{scope} \"$info{filter}\" $info{attrs} $info{redirect}`;
        } else {
            return `ldapsearch -Z -P $info{certdir} -p $info{secure_port} -D \"$info{rootdn}\" -w $myrootdnpw $info{nofold} $info{srch_args} -b \"$info{base}\" -s $info{scope} \"$info{filter}\" $info{attrs} $info{redirect}`;
        }
    } elsif (($info{openldap} eq "yes") && (($info{ldapi} eq "on" && $info{protocol} eq "") || ($info{ldapi} eq "on" && $info{protocol} =~ m/LDAPI/i)) ){  
        # 
        # LDAPI
        #
        if ($< == 0 && $info{autobind} eq "on"){
            return `ldapsearch -LLL -H \"$info{ldapiURL}\" -Y EXTERNAL $info{nofold} $info{srch_args} -b \"$info{base}\" -s $info{scope} \"$info{filter}\" $info{attrs} $info{redirect} 2>/dev/null`;
        } else {
            return `ldapsearch -x -LLL -H \"$info{ldapiURL}\" -D \"$info{rootdn}\" -w $myrootdnpw $info{nofold} $info{srch_args} -b \"$info{base}\" -s $info{scope} \"$info{filter}\" $info{attrs} $info{redirect}`;
        }
    } else {
        # 
        # LDAP
        #
        if($protocol_error eq "yes"){
            print "LDAP)\n";
        }
        if($info{openldap} eq "yes"){
            return `ldapsearch -x -LLL -p $info{port} -h $info{host} -D \"$info{rootdn}\" -w $myrootdnpw $info{nofold} $info{srch_args} -b \"$info{base}\" -s $info{scope} \"$info{filter}\" $info{attrs} $info{redirect}`;
        } else {
            return `ldapsearch -p $info{port} -h $info{host} -D \"$info{rootdn}\" -w $myrootdnpw $info{nofold} $info{srch_args} -b \"$info{base}\" -s $info{scope} \"$info{filter}\" $info{attrs} $info{redirect}`;
        }
    }
}

#
# Check to see if the protocol is supported.  
#
# If it's not supported, start logging the error message - the
# message will be completed by the calling function.
#
sub check_protocol {
    my %info = @_;
    my $txt;
    
    if(($info{protocol} eq "LDAPI" && $info{openldap} eq "no") ||
       ($info{protocol} eq "LDAPI" && $info{ldapi} eq "off") ||
       ($info{protocol} eq "STARTTLS" && ($info{security} eq "" || $info{security} eq "off")) ||
       ($info{protocol} eq "LDAPS" && ($info{security} eq "" || $info{security} eq "off"))
    ){
        if($info{protocol} eq "LDAPI" && $info{openldap} eq "no"){
            $txt = " by the Mozilla LDAP client";
        } else {
            $txt = " by the Directory Server";
        }
        print (STDERR "Protocol $info{protocol} requested, but this protocol is not supported" . $txt . ".\n" .
                      "Using the next most secure protocol (" ); # completed by the caller
        return 1;
    }
    if( ($info{protocol} ne "") && ($info{protocol} ne "STARTTLS" && 
                                    $info{protocol} ne "LDAPS" &&
                                    $info{protocol} ne "LDAPI" && 
                                    $info{protocol} ne "LDAP") )
    {
        print (STDERR "Unknown protocol: $info{protocol}\n");
        return 2;                       
    }
    return 0;
}

1;

# emacs settings
# Local Variables:
# mode:perl
# indent-tabs-mode: nil
# tab-width: 4
# End:
