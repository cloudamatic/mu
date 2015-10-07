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

require 'trollop'

$opts = Trollop::options do
  banner <<-EOS
Listing users:
#{$0}

Adding/modifying users:
#{$0} [-a|-r] [-u <username>] [-e <email>] [-n '<Real Name>'] [-p <password>] [-o <organization>] [-m <email>] <username>

Deleting users:
#{$0} -d <username>

  EOS
  opt :delete, "Delete the user and all of their Chef and filesystem artifacts.", :require => false, :default => false, :type => :boolean
  opt :monitoring_alerts_to, "Send this user's monitoring alerts to an alternate address. Set to 'none' to disable monitoring alerts to this user.", :require => false, :type => :string
  opt :name, "The user's real name. Required when creating a new user.", :require => false, :type => :string
  opt :email, "The user's email address. Required when creating a new user.", :require => false, :type => :string
  opt :admin, "Flag the user as a Mu admin. They will be granted access to the 'mu' (root's) Chef organization.", :require => false, :type => :boolean
  opt :revoke_admin, "Revoke the user's status as a Mu admin. They will be granted access to the 'mu' (root's) Chef organization.", :require => false, :type => :boolean
  opt :org, "Add the user to the named Chef organization, in addition to their default org or orgs.", :require => false, :type => :string
  opt :remove_from_org, "Remove the user to the named Chef organization.", :require => false, :type => :string
  opt :password, "Set a specific password for this user.", :require => false, :type => :string
  opt :generate_password, "Generate and set a random password for this user.", :require => false, :type => :boolean, :default => false
  opt :link_to_ldap, "Link to an existing LDAP user. Typically only needed to map pre-existing Chef users to a separate LDAP or Active Directory domain.", :require => false, :type => :string
end

pp listLDAPUsers
#manageChefUser("jstange", name: "John Stange", set_admin: true, ldap_user: "john.stange.admin")
#manageChefUser("testuser", pass: "fdg620ry1y2", name: "John Q. Public", email: "stange@johnstange.net", ldap_user: "john.stange")
