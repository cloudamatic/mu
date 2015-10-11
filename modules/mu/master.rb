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

    # @param [String]: The account name to display
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

    # Remove a user from Chef, LDAP, and archive their home directory and
    # metadata. 
    def self.deleteUser(user)
      MU::Master::Chef.deleteChefUser(user)
      MU::Master::LDAP.deleteLDAPUser(user)
      # XXX actually do those other two things
    end

    # @return [Array<Hash>]: List of all Mu users
    def self.listUsers
      if !Dir.exist?($MU_CFG['datadir']+"/users")
        MU.log "#{$MU_CFG['datadir']}/users doesn't exist", MU::ERR
        return []
      end
      # LDAP is canonical. Everything else is required to be in sync with it.
      ldap_users = MU::Master::LDAP.listLDAPUsers
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

    # Update Mu's local cache/metadata for the given user, fixing permissions and
    # updating stored values. Create a single-user group for the user, as well.
    # @param user [String]: The user to update
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
      rescue ArgumentError
        %x{/usr/sbin/groupadd "#{user}.mu-user"}
        retry
      end
    end

  end
end
