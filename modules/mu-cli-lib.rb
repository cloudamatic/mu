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
require 'date'
require 'colorize'
require 'fileutils'

############# Work below. Zach, you might want to make this file a loader of
############# some kind for plugins, instead of a big pile of methods.

# Create and return a connection to our directory service. If we've already
# opened one, return that.
@ldap_conn = nil
# @return [Net::LDAP]
def getLDAPConnection
  return @ldap_conn if @ldap_conn
  bind_creds = MU::Groomer::Chef.getSecret(vault: $MU_CFG["ldap"]["svc_acct_vault"], item: $MU_CFG["ldap"]["svc_acct_item"])
  @ldap_conn = Net::LDAP.new(
    :host => $MU_CFG["ldap"]["dcs"].first,
    :encryption => :simple_tls,
    :port => 636,
    :base => $MU_CFG["ldap"]["base_dn"],
    :auth => {
      :method => :simple,
      :username => bind_creds["dn"],
      :password => bind_creds["password"]
    }
  )
  @ldap_conn
end

# Shorthand for fetching the most recent error on the active LDAP connection
def getLDAPErr
  return nil if !@ldap_conn
  return @ldap_conn.get_operation_result.code.to_s+" "+@ldap_conn.get_operation_result.message.to_s
end

# Approximate a current Microsoft timestamp. They count the number of
# 100-nanoseconds intervals (1 nanosecond = one billionth of a second) since
# Jan 1, 1601 UTC.
def getMicrosoftTime
  ms_epoch = DateTime.new(1601,1,1)
  # this is in milliseconds, so multiply it for the right number of zeroes
  elapsed = DateTime.now.strftime("%Q").to_i - ms_epoch.strftime("%Q").to_i
  return elapsed*10000
end

@can_write = nil
# Test whether our LDAP binding user has permissions to create other users,
# manipulate groups, and set passwords. Note that it's *not* fatal if we can't,
# simply a design where most account management happens on the directory side.
# @return [Boolean]
def canWriteLDAP?
  return @can_write if !@can_write.nil?

  conn = getLDAPConnection
  dn = "CN=Mu Testuser #{Process.pid},#{$MU_CFG["ldap"]["base_dn"]}"
  attr = {
    :cn => "Mu Testuser #{Process.pid}",
    :objectclass => ["user"],
    :samaccountname => "mu.testuser.#{Process.pid}",
    :userPrincipalName => "mu.testuser.#{Process.pid}@#{$MU_CFG["ldap"]["domain_name"]}",
    :pwdLastSet => "-1"
  }

  @can_write = true
  if !conn.add(:dn => dn, :attributes => attr)
    MU.log "Couldn't create write-test user #{dn}, operating in read-only LDAP mode", MU::NOTICE, details: getLDAPErr
    return false
  end

  # Make sure we can write various fields that we might need to touch
  [:displayName, :mail, :givenName, :sn].each { |field|
    if !conn.replace_attribute(dn, field, "foo@bar.com")
      MU.log "Couldn't modify write-test user #{dn} field #{field.to_s}, operating in read-only LDAP mode", MU::NOTICE, details: getLDAPErr
      @can_write = false
      break
    end
  }

  # Can we add them to the Mu membership group(s)
  if !conn.modify(:dn => $MU_CFG["ldap"]["admin_group_dn"], :operations => [[:add, :member, dn]])
    MU.log "Couldn't add write-test user #{dn} to group #{$MU_CFG["ldap"]["admin_group_dn"]}, operating in read-only LDAP mode", MU::NOTICE, details: getLDAPErr
    @can_write = false
  end

  if !conn.delete(:dn => dn)
    MU.log "Couldn't delete write-test user #{dn}, operating in read-only LDAP mode", MU::NOTICE
    @can_write = false
  end

  @can_write
end

# @return [Array<String>]
def listLDAPUsers
  conn = getLDAPConnection
  users = {}

  ["admin_group_name", "user_group_name"].each { |group|
    groupname_filter = Net::LDAP::Filter.eq("sAMAccountName", $MU_CFG["ldap"][group])
    group_filter = Net::LDAP::Filter.eq("objectClass", "group")
    member_cns = []
    conn.search(
      :filter => Net::LDAP::Filter.join(groupname_filter, group_filter),
      :attributes => ["member"]
    ) do |item|
      member_cns = item.member.dup
    end
    member_cns.each { |member|
      cn = member.dup.sub(/^CN=([^\,]+?),.*/i, "\\1")
      searchbase = member.dup.sub(/^CN=[^\,]+?,(.*)/i, "\\1")
      conn.search(
        :filter => Net::LDAP::Filter.eq("cn",cn),
        :base => searchbase,
        :attributes => ["sAMAccountName", "displayName", "mail"]
      ) do |acct|
        next if users.has_key?(acct.samaccountname.first)
        users[acct.samaccountname.first] = {}
        users[acct.samaccountname.first]['dn'] = acct.dn
        if group == "admin_group_name"
          users[acct.samaccountname.first]['admin'] = true
        else
          users[acct.samaccountname.first]['admin'] = false
        end
        begin
          users[acct.samaccountname.first]['realname'] = acct.displayname.first
        end rescue NoMethodError
        begin
          users[acct.samaccountname.first]['email'] = acct.mail.first
        end rescue NoMethodError
      end
    }
  }
  users
end

# @param users [Hash]: User metadata of the type returned by listUsers
def printUsersToTerminal(users)
  labeled = false
  users.keys.sort.each { |username|
    data = users[username]
    if data['admin']
      if !labeled
        labeled = true
        puts "Administrators".light_cyan.on_black.bold
      end
      puts "#{username.bold} - #{data['realname']} <#{data['email']}>"
    end
  }
  labeled = false
  users.keys.sort.each { |username|
    data = users[username]
    if !data['admin']
      if !labeled
        labeled = true
        puts "Regular users".light_cyan.on_black.bold
      end
      puts "#{username.bold} - #{data['realname']} <#{data['email']}>"
    end
  }
end

# @param [String]: The account name to display
def printUserDetails(user)
  cur_users = listUsers

  if cur_users.has_key?(user)
    data = cur_users[user]
    puts "#{user.bold} - #{data['realname']} <#{data['email']}>"
    cur_users[user].each_pair { |key, val|
      puts "#{key}: #{val}"
    }
  end
end

# @return [Array<Hash>]: List of all Mu users
def listUsers
  if !Dir.exist?($MU_CFG['datadir']+"/users")
    MU.log "#{$MU_CFG['datadir']}/users doesn't exist", MU::ERR
    return []
  end
  # LDAP is canonical. Everything else is required to be in sync with it.
  ldap_users = listLDAPUsers
  all_user_data = {}
  ldap_users['mu'] = {}
  ldap_users['mu']['admin'] = true
  ldap_users.each_pair { |username, data|
    all_user_data[username] = {}
    userdir = $MU_CFG['datadir']+"/users/#{username}"
    if !Dir.exist?(userdir)
      MU.log "No metadata exists for user #{username}, creating stub directory #{userdir}", MU::WARN
      Dir.mkdir(userdir, 0755)
    end

    ["email", "monitoring_email", "realname", "chef_user", "admin"].each { |field|
      if data.has_key?(field)
        all_user_data[username][field] = data[field]
      elsif File.exist?(userdir+"/"+field)
        all_user_data[username][field] = File.read(userdir+"/"+field).chomp
      elsif ["email", "realname"].include?(field)
        MU.log "Required user field '#{field}' for '#{username}' not set in LDAP or in Mu's disk cache.", MU::WARN
      end
    }
  }
  all_user_data
end

@chef_api = nil
# Create and return a connection to the Chef REST API. If we've already opened
# one, return that.
# @return [Chef::REST]
def chefAPI
  @chef_api ||= Chef::REST.new("https://"+$MU_CFG["public_address"], "pivotal", "/etc/opscode/pivotal.pem", {:api_version => "1"})
  @chef_api
end

# @param user [String]: The Chef username to check
# @return [<Hash>]
def getChefUser(user)
  begin
    Timeout::timeout(45) {
      response = chefAPI.get("users/#{user}")
      return response
    }
  rescue Timeout::Error
    MU.log "Timed out fetching Chef user #{user}, retrying", MU::WARN
    retry
  end rescue Net::HTTPServerException
  return nil
end

# Update Mu's local cache/metadata for the given user, fixing permissions and
# updating stored values. Create a single-user group for the user, as well.
# @param user [String]: The user to update
def setLocalDataPerms(user)
  userdir = $MU_CFG['datadir']+"/users/#{user}"
  begin
    gid = Etc.getgrnam("#{user}.mu-user").gid
    %x{/usr/sbin/usermod -a -G "#{user}.mu-user" "#{user}"}
    Dir.mkdir(userdir, 2750) if !Dir.exist?(userdir)
    Dir.foreach(userdir) { |file|
      next if file == ".."
      File.chown(nil, gid, userdir+"/"+file)
      if File.file?(userdir+"/"+file)
        File.chmod(0640, userdir+"/"+file)
      end
    }
  rescue ArgumentError
    %x{/usr/sbin/groupadd "#{user}.mu-user"}
    retry
  end
end

def deleteLDAPUser(user)
  cur_users = listLDAPUsers

  if cur_users.has_key?(user)
    # Creating a new user
    if canWriteLDAP?
      conn = getLDAPConnection
      dn = "CN=#{cur_users[user]['realname']},#{$MU_CFG["ldap"]["base_dn"]}"
      if !conn.delete(:dn => dn)
        MU.log "Failed to delete #{user} from LDAP.", MU::WARN, details: getLDAPErr
        return false
      end
      MU.log "Removed LDAP user #{user}", MU::NOTICE
      return true
    else
      MU.log "We are in read-only LDAP mode. You must manually delete #{user} from your directory.", MU::WARN
    end
  else
    MU.log "#{user} does not exist in LDAP.", MU::ERR
  end
  false
end

# Call when creating or modifying a user.
# @param user [String]: The username on which to operate
# @param admin [Boolean]: Whether to flag this user as an admin
def manageLDAPUser(user, name: nil, password: nil, email: nil, admin: false)
  cur_users = listLDAPUsers

  first = last = nil
  if !name.nil?
    last = name.split(/\s+/).pop
    first = name.split(/\s+/).shift
  end
  admin_group = $MU_CFG["ldap"]["admin_group_dn"]

  if !cur_users.has_key?(user)
    # Creating a new user
    if canWriteLDAP?
      if password.nil? or email.nil? or name.nil?
        raise MU::MuError, "Missing one or more required fields (name, password, email) creating new user #{user}"
      end
      user_dn = "CN=#{name},#{$MU_CFG["ldap"]["base_dn"]}"
      conn = getLDAPConnection
      attr = {
        :cn => name,
        :displayName => name,
        :objectclass => ["user"],
        :samaccountname => user,
        :givenName => first,
        :sn => last,
        :mail => email,
        :userPassword => password,
        :userPrincipalName => "#{user}@#{$MU_CFG["ldap"]["domain_name"]}",
        :pwdLastSet => "-1"
      }
      if !conn.add(:dn => user_dn, :attributes => attr)
        raise MU::MuError, "Failed to create user #{user} (#{getLDAPErr})"
      end
      attr[:userPassword] = "********"
      MU.log "Created new LDAP user #{user}", details: attr
      groups = [$MU_CFG["ldap"]["user_group_dn"]]
      groups << admin_group if admin
      groups.each { |group|
        if !conn.modify(:dn => group, :operations => [[:add, :member, user_dn]])
          MU.log "Couldn't add new user #{user} to group #{group}. Access to services may be hampered.", MU::WARN, details: getLDAPErr
        end
      }

      # We now require the system to know that the user exists. Sometimes
      # winbind takes a minute to catch on.
      begin
        %x{/usr/bin/getent passwd}
        Etc.getpwnam(user)
      rescue ArgumentError
        sleep 5
        retry
      end
      setLocalDataPerms(user)
      FileUtils.mkdir_p Etc.getpwnam(user).dir+"/.mu"
      FileUtils.chown_R(user, user+".mu-user", Etc.getpwnam(user).dir)
    else
      MU.log "We are in read-only LDAP mode. You must create #{user} in your directory and add it to #{$MU_CFG["ldap"]["user_group_dn"]}. If the user is intended to be an admin, also add it to #{admin_group}.", MU::WARN
      return
    end
  else
    setLocalDataPerms(user)
    # Modifying an existing user
    if canWriteLDAP?
      conn = getLDAPConnection
      user_dn = cur_users[user]['dn']
      if !name.nil? and cur_users[user]['realname'] != name
        MU.log "Updating display name for #{user} to #{name}", MU::NOTICE
        conn.replace_attribute(user_dn, :displayName, name)
        conn.replace_attribute(user_dn, :givenName, first)
        conn.replace_attribute(user_dn, :sn, last)
        cur_users[user]['realname'] = name
      end
      if !email.nil? and cur_users[user]['email'] != email
        MU.log "Updating email for #{user} to #{email}", MU::NOTICE
        conn.replace_attribute(user_dn, :mail, email)
        cur_users[user]['email'] = email
      end
      if !password.nil?
        MU.log "Updating password for #{user}", MU::NOTICE
        if !conn.replace_attribute(user_dn, :userPassword, password)
          MU.log "Couldn't update password for user #{user}.", MU::WARN, details: getLDAPErr
        end
      end
      if admin and !cur_users[user]['admin']
        MU.log "Granting Mu admin privileges to #{user}", MU::NOTICE
        if !conn.modify(:dn => admin_group, :operations => [[:add, :member, user_dn]])
          MU.log "Couldn't add user #{user} (#{user_dn}) to group #{admin_group}.", MU::WARN, details: getLDAPErr
        end
      elsif !admin and cur_users[user]['admin']
        MU.log "Revoking Mu admin privileges from #{user}", MU::NOTICE
        if !conn.modify(:dn => admin_group, :operations => [[:delete, :member, user_dn]])
          MU.log "Couldn't remove user #{user} (#{user_dn}) from group #{admin_group}.", MU::WARN, details: getLDAPErr
        end
      end
    else
    end
  end
  cur_users = listUsers

  ["realname", "email", "monitoring_email"].each { |field|
    next if !cur_users[user].has_key?(field)
    File.open($MU_CFG['datadir']+"/users/#{user}/#{field}", File::CREAT|File::RDWR, 0640) { |f|
      f.puts cur_users[user][field]
    }
  }
  setLocalDataPerms(user)

end

def deleteChefUser(user)
  cur_users = listUsers
  chef_user = nil
  if !cur_users.has_key?(user) and getChefUser(user) == nil
    MU.log "No such Chef or LDAP user #{user}", MU::ERR
    return false
  elsif cur_users.has_key?(user) and cur_users[user].has_key?("chef_user")
    chef_user = cur_users[user]["chef_user"]
  else
    chef_user = user
  end

  begin
    Timeout::timeout(45) {
      response = chefAPI.delete("users/#{chef_user}")
    }
    MU.log "Removed Chef user #{chef_user}", MU::NOTICE
  rescue Timeout::Error
    MU.log "Timed out removing Chef user #{chef_user}, retrying", MU::WARN
    retry
  rescue Net::HTTPServerException => e
    if !e.message.match(/^404 /)
      MU.log "Couldn't remove Chef user #{chef_user}: #{e.message}", MU::WARN
    end
  end
#XXX delete the org that shares their name, too
end

# @param user [String]: The regular, system name of the user
# @param chef_user [String]: The user's Chef username, which may differ
def createUserClientCfg(user, chef_user)
  chefdir = Etc.getpwnam(user).dir+"/.chef"
  FileUtils.mkdir_p chefdir
  File.open(chefdir+"/client.rb.tmp.#{Process.pid}", File::CREAT|File::RDWR, 0640) { |f|
    f.puts "log_level        :info"
    f.puts "log_location     STDOUT"
    f.puts "chef_server_url  'https://#{$MU_CFG["public_address"]}/organizations/#{chef_user}'"
    f.puts "validation_client_name '#{chef_user}-validator'"
  }
  if !File.exists?("#{chefdir}/client.rb") or
      File.read("#{chefdir}/client.rb") != File.read("#{chefdir}/client.rb.tmp.#{Process.pid}")
    File.rename(chefdir+"/client.rb.tmp.#{Process.pid}", chefdir+"/client.rb")
    FileUtils.chown_R(user, user+".mu-user", Etc.getpwnam(user).dir+"/.chef")
    MU.log "Generated #{chefdir}/client.rb"
  else
    File.unlink("#{chefdir}/client.rb.tmp.#{Process.pid}")
  end
end

# @param user [String]: The regular, system name of the user
# @param chef_user [String]: The user's Chef username, which may differ
def createUserKnifeCfg(user, chef_user)
  chefdir = Etc.getpwnam(user).dir+"/.chef"
  FileUtils.mkdir_p chefdir
  File.open(chefdir+"/knife.rb.tmp.#{Process.pid}", File::CREAT|File::RDWR, 0640) { |f|
    f.puts "log_level                :info"
    f.puts "log_location             STDOUT"
    f.puts "node_name                '#{chef_user}'"
    f.puts "client_key               '#{chefdir}/#{chef_user}.user.key'"
    f.puts "validation_client_name   '#{chef_user}-validator'"
    f.puts "validation_key           '$chef_cache/#{chef_user}.org.key'"
    f.puts "chef_server_url 'https://#{$MU_CFG["public_address"]}/organizations/#{chef_user}'"
    f.puts "chef_server_root 'https://#{$MU_CFG["public_address"]}/organizations/#{chef_user}'"
    f.puts "syntax_check_cache_path  '#{chef_user}/syntax_check_cache'"
    f.puts "cookbook_path [ '#{chef_user}/cookbooks', '#{chef_user}/site_cookbooks' ]"
    f.puts "knife[:vault_mode] = 'client'"
    f.puts "knife[:vault_admins] = ['#{chef_user}']"
    f.puts "verify_api_cert    false"
    f.puts "ssl_verify_mode    :verify_none"
  }
  if !File.exists?("#{chefdir}/knife.rb") or
      File.read("#{chefdir}/knife.rb") != File.read("#{chefdir}/knife.rb.tmp.#{Process.pid}")
    File.rename(chefdir+"/knife.rb.tmp.#{Process.pid}", chefdir+"/knife.rb")
    FileUtils.chown_R(user, user+".mu-user", Etc.getpwnam(user).dir+"/.chef")
    MU.log "Generated #{chefdir}/knife.rb"
  else
    File.unlink("#{chefdir}/knife.rb.tmp.#{Process.pid}")
  end
end

# Save a Chef key into both Mu's user metadata cache and the user's ~/.chef.
# @param user [String]: The (system) name of the user.
# @param keyname [String]: The name of the key, e.g. myuser.user.key or myuser.org.key
# @param key [String]: The Chef private key to save
def saveChefKey(user, keyname, key)
  FileUtils.mkdir_p $MU_CFG['datadir']+"/users/#{user}"
  FileUtils.mkdir_p Etc.getpwnam(user).dir+"/.chef"
  [$MU_CFG['datadir']+"/users/#{user}/#{keyname}", Etc.getpwnam(user).dir+"/.chef/#{keyname}"].each { |keyfile|
    if File.exist?(keyfile)
      File.rename(keyfile, keyfile+"."+Time.now.to_i.to_s)
    end
    File.open(keyfile, File::CREAT|File::RDWR, 0640) { |f|
      f.puts key
    }
    MU.log "Wrote Chef key #{keyname} to #{keyfile}", MU::DEBUG
  }
  FileUtils.chown_R(user, user+".mu-user", Etc.getpwnam(user).dir+"/.chef")
end

# Call when creating or modifying a user. While Chef technically does
# communicate with LDAP, it's only for the web UI, which we don't even use.
# Keys still need to be managed, and sometimes the username can't even match
# the LDAP one due to Chef's weird restrictions.
def manageChefUser(chef_user, name: nil, email: nil, orgs: [], remove_orgs: [], admin: false, ldap_user: nil, pass: nil)
  orgs = [] if orgs.nil?
  remove_orgs = [] if remove_orgs.nil?

  # In this shining future, there are no situations where we will *not* have
  # an LDAP user to link to.
  ldap_user = chef_user.dup if ldap_user.nil?
  if chef_user.gsub!(/\./, "")
    MU.log "Stripped . from username to create Chef user #{chef_user}.\nSee: https://github.com/chef/chef-server/issues/557", MU::NOTICE
    orgs.delete(ldap_user)
  end

  orgs << chef_user if !orgs.include?(chef_user)
  if admin
    orgs << "mu"
  else
    remove_orgs << "mu"
  end

  if remove_orgs.include?(chef_user)
    raise MU::MuError, "Can't remove Chef user #{chef_user} from the #{chef_user} org"
  end
  if (orgs & remove_orgs).size > 0
    raise MU::MuError, "Cannot both add and remove from the same Chef org"
  end

  setLocalDataPerms(ldap_user)

  first = last = nil
  if !name.nil?
    last = name.split(/\s+/).pop
    first = name.split(/\s+/).shift
  end
  mangled_email = email.dup

  ext = getChefUser(chef_user)

  # This user exists and we've passed something new, so modify it
  if ext
    retries = 0
    begin
      user_data = {
        :username => chef_user,
        :recovery_authentication_enabled => false,
        :external_authentication_uid => ldap_user
      }
      ext.each_pair { |key, val| user_data[key.to_sym] = val }
      user_data[:display_name] = name.dup if !name.nil?
      user_data[:first_name] = first if !first.nil?
      user_data[:last_name] = last if !last.nil?
      user_data[:password] = pass.dup if !pass.nil?
      if !email.nil?
        if !user_data[:email].nil?
          mailbox, host = mangled_email.split(/@/)
          if !user_data[:email].match(/^#{Regexp.escape(mailbox)}\+.+?@#{Regexp.escape(host)}$/)
            user_data[:email] = mangled_email
          end
        else
          user_data[:email] = mangled_email
        end
      end
      Timeout::timeout(45) {
        response = chefAPI.put("users/#{chef_user}", user_data)
        user_data[:password] = "********"
        MU.log "Chef user #{chef_user} already exists, updating", details: user_data
        if response.has_key?("chef_key") and response["chef_key"].has_key?("private_key")
          saveChefKey(ldap_user, "#{ldap_user}.user.key", response["chef_key"]["private_key"])
        end
      }
      createUserKnifeCfg(ldap_user, chef_user)
      createUserClientCfg(ldap_user, chef_user)
      %{/bin/su "#{ldap_user}" -c "cd && /opt/chef/bin/knife ssl fetch"}
      return true
    rescue Timeout::Error
      MU.log "Timed out modifying Chef user #{chef_user}, retrying", MU::WARN
      retry
    rescue Net::HTTPServerException => e
      # Work around Chef's baffling inability to use the same email address for
      # more than one user.
      # https://github.com/chef/chef-server/issues/59
      if e.message.match(/409/) and !user_data[:email].match(/\+/)
        if retries > 3
          raise MU::MuError, "Got #{e.message} modifying Chef user #{chef_user} (#{user_data})"
        end
        sleep 5
        retries = retries + 1
        mangled_email.sub!(/@/, "+"+(0...8).map { ('a'..'z').to_a[rand(26)] }.join+"@")
        retry
      end
      MU.log "Failed to update user #{chef_user}: #{e.message}", MU::ERR, details: user_data
      raise e
    end

  # This user doesn't exist, create it
  else
    if name.nil? or email.nil?
      MU.log "Error creating Chef user #{chef_user}: Must supply real name and email address", MU::ERR
      return
    end

    # We don't ever really need this password, so generate a random one if none
    # was supplied.
    if pass.nil?
      pass = (0...8).map { ('a'..'z').to_a[rand(26)] }.join
    end
    user_data = {
      :username => chef_user.dup,
      :first_name => first,
      :last_name => last,
      :display_name => name.dup,
      :email => email.dup,
      :create_key => true,
      :recovery_authentication_enabled => false,
      :external_authentication_uid => ldap_user.dup,
      :password => pass.dup
    }
    begin
      Timeout::timeout(45) {
        response = chefAPI.post("users", user_data)
        MU.log "Created Chef user #{chef_user}", details: response
        saveChefKey(ldap_user, "#{ldap_user}.user.key", response["chef_key"]["private_key"])
        createUserKnifeCfg(ldap_user, chef_user)
        createUserClientCfg(ldap_user, chef_user)
      }
      %{/bin/su "#{ldap_user}" -c "cd && /opt/chef/bin/knife ssl fetch"}
      return true
    rescue Timeout::Error
      MU.log "Timed out creating Chef user #{chef_user}, retrying", MU::WARN
      retry
    rescue Net::HTTPServerException => e
      # Work around Chef's baffling inability to use the same email address for
      # more than one user.
      # https://github.com/chef/chef-server/issues/59
      if e.message.match(/409/) and !user_data[:email].match(/\+/)
        user_data[:email].sub!(/@/, "+"+(0...8).map { ('a'..'z').to_a[rand(26)] }.join+"@")
        retry
      end
      MU.log "Bad response when creating Chef user #{chef_user}: #{e.message}", MU::ERR, details: user_data
      return false
    end
  end
  if ldap_user != chef_user
    File.open($MU_CFG['datadir']+"/users/#{ldap_user}/chef_user", File::CREAT|File::RDWR, 0640) { |f|
      f.puts chef_user
    }
  end

  # Meddling in the user's home directory
  # Make sure they'll trust the Chef server's SSL certificate

  setLocalDataPerms(ldap_user)
  true
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
