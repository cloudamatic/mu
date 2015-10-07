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

require File.realpath(File.expand_path(File.dirname(__FILE__)+"/mu-load-config.rb"))
# now we have our global config available as the read-only hash $MU_CFG
require 'mu'
require 'net-ldap'

# @return [Net::LDAP]
def getLDAPConnection
  bind_creds = MU::Groomer::Chef.getSecret(vault: $MU_CFG["ldap"]["svc_acct_vault"], item: $MU_CFG["ldap"]["svc_acct_item"])
  ldap = Net::LDAP.new(
    :host => $MU_CFG["ldap"]["dcs"].first,
#    :encryption => :simple_tls,
    :base => $MU_CFG["ldap"]["base_dn"],
    :auth => {
      :method => :simple,
      :username => bind_creds["dn"],
      :password => bind_creds["password"]
    }
  )
  groupname_filter = Net::LDAP::Filter.eq("sAMAccountName", $MU_CFG["ldap"]["admin_group_name"])
  group_filter = Net::LDAP::Filter.eq("objectClass", "group")
  member_cns = []
  ldap.search(
    :filter => Net::LDAP::Filter.join(groupname_filter, group_filter),
    :attributes => ["member"]
  ) do |item|
    member_cns = item.member.dup
  end
  users = []
  member_cns.each { |member|
    cn = member.sub(/^CN=([^,]+),OU=.*/i, "#{$1}")
    ldap.search(
      :filter => Net::LDAP::Filter.eq("cn",cn),
      :attributes => ["sAMAccountName"]
    ) do |acct|
      users << acct.samaccountname
    end
  }
  users
end

def listLDAPUsers
  conn = getLDAPConnection
end

############# Work below. Zach, you might want to make this file a loader of
############# some kind for plugins, instead of a big pile of methods.

def manageChefUser(user, pass: nil, name: nil, email: nil, org: nil, set_admin: false, set_normal: false, replace: false, ldap_user: nil)

  rest = Chef::REST.new("https://"+$MU_CFG["public_address"], "pivotal", "/etc/opscode/pivotal.pem", {:api_version => "1"})

  # In this shining future, there are no situations where we will *not* have
  # an LDAP user to link to.
  ldap_user = user.dup if ldap_user.nil?
  if user.gsub!(/\./, "")
    MU.log "Stripped . from username to create Chef user #{user}.\nSee: https://github.com/chef/chef-server/issues/557", MU::NOTICE
  end

  first = last = nil
  if !name.nil?
    last = name.split(/\s+/).pop
    first = name.split(/\s+/).shift
  end

  # Check for existence
  user_exists = false
  begin
    rest.get("users/#{user}")
    user_exists = true
  end rescue Net::HTTPServerException

  # This user exists, modify it
  if user_exists
    begin
      user_data = {
        :username => user,
        :recovery_authentication_enabled => false,
        :external_authentication_uid => ldap_user
      }
      user_data[:display_name] = name if !name.nil?
      user_data[:email] = email if !email.nil?
      user_data[:first_name] = first if !first.nil?
      user_data[:last_name] = last if !last.nil?
      user_data[:password] = pass if !pass.nil?
      response = rest.put("users/#{user}", user_data)
      user_data[:password] = "********"
      MU.log "Chef user #{user} already exists, modified", MU::NOTICE, details: user_data
      return
    rescue Net::HTTPServerException => e
      # Work around Chef's baffling inability to use the same email address for
      # more than one user.
      # https://github.com/chef/chef-server/issues/59
      if e.message.match(/409/) and !user_data[:email].match(/\+/)
        user_data[:email].sub!(/@/, "+"+(0...8).map { ('a'..'z').to_a[rand(26)] }.join+"@")
        retry
      end
      MU.log "Failed to update user #{user}: #{e.message}", MU::ERR, details: user_data
      raise e
    end
  # This user doesn't exist, create it
  else
    if name.nil? or email.nil?
      MU.log "Error creating Chef user #{user}: Must supply real name and email address", MU::ERR
      return
    end
    MU.log "Creating Chef user #{user}"

    # We don't ever really need this password, so generate a random one if none
    # was supplied.
    if pass.nil?
      pass = (0...8).map { ('a'..'z').to_a[rand(26)] }.join
    end
    user_data = {
      :username => user,
      :first_name => first,
      :last_name => last,
      :display_name => name,
      :email => email,
      :recovery_authentication_enabled => false,
      :external_authentication_uid => ldap_user,
      :password => (0...8).map { ('a'..'z').to_a[rand(26)] }.join
    }
    begin
      response = rest.post("users", user_data)
      pp response
    rescue Net::HTTPServerException => e
      # Work around Chef's baffling inability to use the same email address for
      # more than one user.
      # https://github.com/chef/chef-server/issues/59
      if e.message.match(/409/) and !user_data[:email].match(/\+/)
        user_data[:email].sub!(/@/, "+"+(0...8).map { ('a'..'z').to_a[rand(26)] }.join+"@")
        retry
      end
      MU.log "Bad response when creating Chef user #{user}: #{e.message}", MU::ERR, details: user_data
    end
  end
end

# Mangle Chef's server config to speak to LDAP
def configureChefForLDAP
if $MU_CFG.has_key?("ldap")
    bind_creds = MU::Groomer::Chef.getSecret(vault: $MU_CFG["ldap"]["svc_acct_vault"], item: $MU_CFG["ldap"]["svc_acct_item"])
    vars = {
      "server_url" => $MU_CFG["public_address"],
      "ldap" => true,
      "base_dn" => $MU_CFG["ldap"]["base_dn"],
      "group_dn" => $MU_CFG["ldap"]["admin_group_dn"],
      "dc" => $MU_CFG["ldap"]["dcs"].first,
      "bind_dn" => bind_creds["dn"],
      "bind_pw" => bind_creds["password"],
    }
    chef_cfgfile = "/etc/opscode/chef-server.rb"
    chef_tmpfile = "#{chef_cfgfile}.tmp.#{Process.pid}"
    File.open(chef_tmpfile, File::CREAT|File::RDWR, 0644) { |f|
      f.puts Erubis::Eruby.new(File.read("chef-server.rb.erb")).result(vars)
    }
    new = File.read(chef_tmpfile)
    current = File.read(chef_cfgfile)
    if new != current
      MU.log "Updating #{chef_cfgfile}", MU::NOTICE
      File.rename(chef_tmpfile, chef_cfgfile)
      system("/opt/opscode/bin/chef-server-ctl reconfigure")
    else
      File.unlink(chef_tmpfile)
    end
  end
end
