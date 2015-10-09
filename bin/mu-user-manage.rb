#!/usr/local/ruby-current/bin/ruby
# Copyright:: Copyright (c) 2014 eGlobalTech, Inc., all rights reserved
#
# Licensed under the BSD-3 license (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License in the root of the project or at
#
#     http://egt-labs.com/mu/LICENSE.html
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


require File.realpath(File.expand_path(File.dirname(__FILE__), "mu-cli-lib.rb"))

if Etc.getpwuid(Process.uid).name != "root"
  MU.log "#{$0} can only be run as root", MU::ERR
  exit 1
end

require 'trollop'
require 'simple-password-gen'

$opts = Trollop::options do
  banner <<-EOS
Listing users:
#{$0}

Adding/modifying users:
#{$0} [-i] [-a|-r] [-e <email>] [-n '<Real Name>'] [-p <password>|-g] [-o <chef_org>] [-v <chef_org>] [-m <email>] [-l <chef_user>] <username>

Deleting users:
#{$0} [-i] -d <username>

  EOS
  opt :delete, "Delete the user and all of their Chef and filesystem artifacts.", :require => false, :default => false, :type => :boolean
  opt :monitoring_alerts_to, "Send this user's monitoring alerts to an alternate address. Set to 'none' to disable monitoring alerts to this user.", :require => false, :type => :string
  opt :name, "The user's real name. Required when creating a new user.", :require => false, :type => :string
  opt :email, "The user's email address. Required when creating a new user.", :require => false, :type => :string
  opt :admin, "Flag the user as a Mu admin. They will be granted sudo access to the 'mu' (root's) Chef organization.", :require => false, :type => :boolean
  opt :revoke_admin, "Revoke the user's status as a Mu admin. Access to the 'mu' (root) Chef organization and sudoers will be removed.", :require => false, :type => :boolean
  opt :org, "Add the user to the named Chef organization, in addition to their default org or orgs.", :require => false, :type => :strings
  opt :remove_from_org, "Remove the user to the named Chef organization.", :require => false, :type => :strings
  opt :password, "Set a specific password for this user.", :require => false, :type => :string
  opt :generate_password, "Generate and set a random password for this user.", :require => false, :type => :boolean, :default => false
  opt :link_to_chef_user, "Link to an existing Chef user. Chef's naming restrictions sometimes necessitate having a different account name than everything else. Also useful for linking a pre-existing Chef user to the rest of a Mu account.", :require => false, :type => :string
  opt :interactive, "Interactive mode. Will prompt for missing fields.", :require => false, :type => :boolean
end

Dir.mkdir($MU_CFG['datadir']+"/users", 0755) if !Dir.exist?($MU_CFG['datadir']+"/users")

if $opts[:admin] and $opts[:revoke_admin]
  MU.log "Cannot both add and revoke admin access", MU::ERR
  Trollop::educate
end
if $opts[:password] and $opts[:generate_password]
  MU.log "Cannot both specify a password and generate a password", MU::ERR
  Trollop::educate
end

if $opts[:org] and $opts[:remove_from_org] and ($opts[:org] & $opts[:remove_from_org]).size > 0
  MU.log "Cannot both add and remove from the same Chef org", MU::ERR
  exit 1
end

$password = nil
if $opts[:generate_password]
  $password = MU.generateWindowsPassword
elsif $opts[:password]
  $password = $opts[:password]
end

$cur_users = listUsers
canWriteLDAP?

if !ARGV[0] or ARGV[0].empty?
  bail = false
  $opts.each_key { |opt|
    if $opts[opt] and !opt.to_s.match(/_given$/)
      MU.log "Must specify a username with the '#{opt.to_s}' option", MU::ERR
      bail = true
    end
  }
  Trollop::educate if bail
  printUsersToTerminal($cur_users)
  exit 0
end
$username = ARGV[0]

[:org, :remove_from_org].each { |org_field|
  bail = false
  if $opts[org_field]
    $opts[org_field].each { |org|
      if !org.match(/^[a-z_][a-z0-9_]{0,30}$/i)
        MU.log "'#{org}' is not a valid Chef org name", MU::ERR
        bail = true
      end
    }
  end
  exit 1 if bail
}

[:email, :monitoring_alerts_to].each { |email_field|
  bail = false
  if $opts[email_field] and !$opts[email_field].match(/^[A-Z0-9\._%\+\-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}$/i)
    MU.log "'#{$opts[email_field]}' is not a valid email address", MU::ERR
    bail = true
  end
  exit 1 if bail
}

if $opts[:name] and !$opts[:name].match(/ /)
  MU.log "'name' field must consist of at least two words (saw '#{$opts[:name]}')", MU::ERR
  exit 1
end

if $opts[:link_to_chef_user] and !chefUserExists?($opts[:link_to_chef_user])
  MU.log "Requested link to Chef user '#{$opts[:link_to_chef_user]}', but that user doesn't exist", MU::ERR
  exit 1
end

# Delete an existing account
if $opts[:delete]
  bail = false
  if !$cur_users.has_key?($username)
    MU.log "User #{$username} does not exist, cannot delete", MU::ERR
    bail = true
  end
  $opts.each_key { |opt|
    if opt.to_s != "delete" and $opts[opt] and !opt.to_s.match(/_given$/)
      MU.log "Ignoring extraneous option '#{opt.to_s}' in delete", MU::WARN
    end
  }
  exit 1 if bail

  deleteLDAPUser($username)

else
  create = false
  if !$cur_users.has_key?($username)
    $cur_users[$username] = {} if !$cur_users.has_key?($username)
    create = true
  end

  $cur_users[$username]['realname'] = $opts[:name] if $opts[:name]
  $cur_users[$username]['email'] = $opts[:email] if $opts[:email]
  $cur_users[$username]['admin'] = true if $opts[:admin]
  $cur_users[$username]['admin'] = false if $opts[:revoke_admin]
  if $opts[:link_to_chef_user]
    $cur_users[$username]['chef_user'] = $opts[:link_to_chef_user].dup
  else
    $cur_users[$username]['chef_user'] = $username.dup
  end

  # Validate for modifying an existing account
  if !create
puts "modifying #{$username}"
    bail = false
    if !$cur_users[$username].has_key?("email") and !$opts[:email]
      MU.log "#{$username} does not have an email address set in LDAP, must supply one with -e to modify this account.", MU::ERR
      bail = true
    end
    if !$cur_users[$username].has_key?("realname") and !$opts[:name]
      MU.log "#{$username} does not have a display name set in LDAP, must supply one with -n to modify this account.", MU::ERR
      bail = true
    end
    exit 1 if bail

  # Validate for creating a new account
  else
    bail = false

    if !$opts[:email]
      MU.log "#{$username} does not have an email address set in LDAP, must supply one with -e.", MU::ERR
      bail = true
    end
    if !$opts[:name]
      MU.log "#{$username} does not have a display name set in LDAP, must supply one with -n.", MU::ERR
      bail = true
    end
    if $password.nil?
      MU.log "Must supply a password for #{$username} with -p (raw string), -g (generate), or -i (interactive mode).", MU::ERR
      bail = true
    end
    exit 1 if bail

  end

  # These routines gracefully figure out whether they're adding or modifying.
  manageLDAPUser(
    $username,
    name: $cur_users[$username]['realname'],
    email: $cur_users[$username]['email'],
    password: $password,
    admin: $cur_users[$username]['admin']
  )
#  manageChefUser(
#    $cur_users[$username]['chef_user'],
#    name: $cur_users[$username]['realname'],
#    email: $cur_users[$username]['email'],
#    admin: $cur_users[$username]['admin'],
#    ldap_user: $username
#  )
end

printUsersToTerminal(listUsers)

# If we asked for interactive mode, fill in the blanks
if $opts.interactive
end
