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


module MU

  class Master
    require 'date'
    require 'colorize'
    require 'fileutils'
    autoload :Chef, 'mu/master/chef'
    autoload :LDAP, 'mu/master/ldap'

    # @param users [Hash]: User metadata of the type returned by listUsers
    def self.printUsersToTerminal(users)
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

    # @param user [String]: The account name to display
    def self.printUserDetails(user)
      cur_users = listUsers

      if cur_users.has_key?(user)
        data = cur_users[user]
        puts "#{user.bold} - #{data['realname']} <#{data['email']}>"
        cur_users[user].each_pair { |key, val|
          puts "#{key}: #{val}"
        }
      end
    end

    # Create and/or update a user as appropriate (Chef, LDAP, et al).
    # @param username [String]: The canonical username to modify.
    # @param chef_username [String]: The Chef username, if different
    # @param name [String]: Real name (Given Surname). Required for new accounts.
    # @param email [String]: Email address of the user. Required for new accounts.
    # @param password [String]: A password to set. Required for new accounts.
    # @param admin [Boolean]: Whether or not the user should be a Mu admin.
    # @param orgs [Array<String>]: Extra Chef organizations to which to add the user.
    # @param remove_orgs [Array<String>]: Chef organizations from which to remove the user.
    def self.manageUser(
      username,
      chef_username: nil,
      name: nil,
      email: nil,
      password: nil,
      admin: false,
      orgs: [],
      remove_orgs: []
    )
      create = false
      cur_users = listUsers
      create = true if !cur_users.has_key?(username)
      if !MU::Master::LDAP.manageUser(username, name: name, email: email, password: password, admin: admin)
        deleteUser(username)
        return false
      end
      begin
        Etc.getpwnam(username)
      rescue ArgumentError
        return false
      end
      %x{/bin/su - #{username} -c "ls > /dev/null"}
      if !MU::Master::Chef.manageUser(chef_username, ldap_user: username, name: name, email: email, admin: admin, orgs: orgs, remove_orgs: remove_orgs) and create
        deleteUser(username)
        return false
      end
      %x{/bin/su - #{username} -c "/opt/chef/bin/knife ssl fetch 2>&1 > /dev/null"}
      setLocalDataPerms(username)
      if create
        home = Etc.getpwnam(username).dir
        FileUtils.mkdir_p home+"/.mu/var"
        FileUtils.chown_R(username, username+".mu-user", Etc.getpwnam(username).dir)
        %x{/bin/su - #{username} -c "ls > /dev/null"}
        vars = {
          "home" => home,
          "installdir" => $MU_CFG['installdir']
        }
        File.open(home+"/.murc", "w+", 0640){ |f|
          f.puts Erubis::Eruby.new(File.read("#{$MU_CFG['libdir']}/install/dot-murc.erb")).result(vars)
        }
        File.open(home+"/.bashrc", "a"){ |f|
          f.puts "source #{home}/.murc"
        }
        FileUtils.chown_R(username, username+".mu-user", Etc.getpwnam(username).dir)
        %x{/sbin/restorecon -r /home}
      end
    end


    # Remove a user from Chef, LDAP, and archive their home directory and
    # metadata. 
    # @param user [String]
    def self.deleteUser(user)
      deletia = []
      begin
        home = Etc.getpwnam(user).dir
        if Dir.exist?(home)
          archive = "/home/#{user}.home.#{Time.now.to_i.to_s}.tar.gz"
          %x{/bin/tar -czpf #{archive} #{home}}
          MU.log "Archived #{user}'s home directory to #{archive}"
          deletia << home
        end
      end rescue ArgumentError
      if Dir.exist?("#{$MU_CFG['datadir']}/users/#{user}")
        archive = "#{$MU_CFG['datadir']}/#{user}.metadata.#{Time.now.to_i.to_s}.tar.gz"
        %x{/bin/tar -czpf #{archive} #{$MU_CFG['datadir']}/users/#{user}}
        MU.log "Archived #{user}'s Mu metadata cache to #{archive}"
        deletia << "#{$MU_CFG['datadir']}/users/#{user}"
      end
      MU::Master::Chef.deleteUser(user)
      MU::Master::LDAP.deleteUser(user)
      FileUtils.rm_rf(deletia)
      %x{/usr/sbin/groupdel "#{user}.mu-user"}
    end

    @scratchpad_semaphore = Mutex.new
    # Store a secret for end-user retrieval via MommaCat's public interface.
    # @param text [String]: 
    def self.storeScratchPadSecret(text)
      raise MuError, "Cannot store an empty secret in scratchpad" if text.nil? or text.empty?
      @scratchpad_semaphore.synchronize {
        itemname = nil
        data = {
          "secret" => Base64.urlsafe_encode64(text),
          "timestamp" => Time.now.to_i.to_s
        }
        begin
          itemname = Password.pronounceable(32)
          # Make sure this itemname isn't already in use
          MU::Groomer::Chef.getSecret(vault: "scratchpad", item: itemname)
        rescue MU::Groomer::Chef::MuNoSuchSecret
          MU::Groomer::Chef.saveSecret(vault: "scratchpad", item: itemname, data: data)
          return itemname
        end while true
      }
    end

    # Retrieve a secret stored by #storeScratchPadSecret, then delete it.
    # @param itemname [String]: The identifier of the scratchpad secret.
    def self.fetchScratchPadSecret(itemname)
      @scratchpad_semaphore.synchronize {
        data = MU::Groomer::Chef.getSecret(vault: "scratchpad", item: itemname)
        raise MuError, "Malformed scratchpad secret #{itemname}" if !data.has_key?("secret")
        MU::Groomer::Chef.deleteSecret(vault: "scratchpad", item: itemname)
        return Base64.urlsafe_decode64(data["secret"])
      }
    end

    # @return [Array<Hash>]: List of all Mu users, with pertinent metadata.
    def self.listUsers
      if !Dir.exist?($MU_CFG['datadir']+"/users")
        MU.log "#{$MU_CFG['datadir']}/users doesn't exist", MU::ERR
        return []
      end
      # LDAP is canonical. Everything else is required to be in sync with it.
      ldap_users = MU::Master::LDAP.listUsers
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

    # Update Mu's local cache/metadata for the given user, fixing permissions
    # and updating stored values. Create a single-user group for the user, as
    # well.
    # @param user [String]: The user to update
    # @return [Integer]: The gid of the user's default group
    def self.setLocalDataPerms(user)
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
        return gid
      rescue ArgumentError
        %x{/usr/sbin/groupadd "#{user}.mu-user"}
        retry
      end
    end

  end
end
