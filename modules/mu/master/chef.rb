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
    class Chef

      @chef_api = nil
      # Create and return a connection to the Chef REST API. If we've already opened
      # one, return that.
      # @return [Chef::REST]
      def self.chefAPI
        @chef_api ||= ::Chef::REST.new("https://"+$MU_CFG["public_address"], "pivotal", "/etc/opscode/pivotal.pem", {:api_version => "1"})
        @chef_api
      end

      # @param user [String]: The Chef username to check
      # @return [<Hash>]
      def self.getChefUser(user)
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

      def self.deleteChefUser(user)
        cur_users = MU::Master.listUsers
        chef_user = nil
        if cur_users.has_key?(user) and cur_users[user].has_key?("chef_user")
          chef_user = cur_users[user]["chef_user"]
        else
          chef_user = user
        end

        begin
          Timeout::timeout(45) {
            response = chefAPI.delete("users/#{chef_user}")
          }
          MU.log "Removed Chef user #{chef_user}", MU::NOTICE
          return true
        rescue Timeout::Error
          MU.log "Timed out removing Chef user #{chef_user}, retrying", MU::WARN
          retry
        rescue Net::HTTPServerException => e
          if !e.message.match(/^404 /)
            MU.log "Couldn't remove Chef user #{chef_user}: #{e.message}", MU::WARN
          else
            MU.log "#{chef_user} does not exist in Chef, cannot remove.", MU::ERR
          end
          return false
        end
      #XXX delete the org that shares their name, too
      end

      # @param user [String]: The regular, system name of the user
      # @param chef_user [String]: The user's Chef username, which may differ
      def self.createUserClientCfg(user, chef_user)
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
      def self.createUserKnifeCfg(user, chef_user)
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
      def self.saveChefKey(user, keyname, key)
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
      def self.manageChefUser(chef_user, name: nil, email: nil, orgs: [], remove_orgs: [], admin: false, ldap_user: nil, pass: nil)
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

      # Mangle Chef's server config to speak to LDAP. Technically this only
      # impacts logins for their web UI, which we currently don't use.
      def self.configureChefForLDAP
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
    end
  end
end
