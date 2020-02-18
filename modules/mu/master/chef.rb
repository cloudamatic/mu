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

    # Routines for managing Chef users and orgs on the Mu Master.
    class Chef

      @chef_api = nil
      # Create and return a connection to the Chef REST API. If we've already opened
      # one, return that.
      # @return [Chef::ServerAPI]
      def self.chefAPI
        @chef_api ||= ::Chef::ServerAPI.new("https://#{$MU_CFG["public_address"]}:7443", client_name: "pivotal", signing_key_filename: "/etc/opscode/pivotal.pem")
        @chef_api
      end

      # @param user [String]: The user whose data we'll be fetching from the Chef API.
      # @return [<Hash>]
      def self.getUser(user)
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

      # Remove an organization from the Chef server.
      # @param org [String]
      # @return [Boolean]
      def self.deleteOrg(org)
        begin
          Timeout::timeout(45) {
            chefAPI.delete("organizations/#{org}")
          }
          MU.log "Removed Chef organization #{org}", MU::NOTICE
          return true
        rescue Timeout::Error
          MU.log "Timed out removing Chef organization #{org}, retrying", MU::WARN
          retry
        rescue Net::HTTPServerException => e
          if !e.message.match(/^404 /)
            MU.log "Couldn't remove Chef organization #{org}: #{e.message}", MU::WARN
          else
            MU.log "#{org} does not exist in Chef, cannot remove.", MU::DEBUG
            return false
          end
          return false
        end
      end

      # Remove a user account from the Chef server.
      # @param user [String]
      # @return [Boolean]
      def self.deleteUser(user)
        cur_users = MU::Master.listUsers
        chef_user = nil
        if cur_users.has_key?(user) and cur_users[user].has_key?("chef_user")
          chef_user = cur_users[user]["chef_user"]
        else
          chef_user = user
        end

        deleteOrg(chef_user)

        begin
          Timeout::timeout(45) {
            chefAPI.delete("users/#{chef_user}")
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
            MU.log "#{chef_user} does not exist in Chef, cannot remove.", MU::DEBUG
            return false
          end
          return false
        end
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
        if !File.exist?("#{chefdir}/client.rb") or
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
          f.puts "validation_key           '#{chefdir}/#{chef_user}.org.key'"
          f.puts "chef_server_url 'https://#{$MU_CFG["public_address"]}:7443/organizations/#{chef_user}'"
          f.puts "chef_server_root 'https://#{$MU_CFG["public_address"]}:7443/organizations/#{chef_user}'"
          f.puts "syntax_check_cache_path  '#{chefdir}/syntax_check_cache'"
          f.puts "cookbook_path [ '#{chefdir}/cookbooks', '#{chefdir}/site_cookbooks' ]"
          f.puts "knife[:vault_mode] = 'client'"
          f.puts "knife[:vault_admins] = ['#{chef_user}']"
          # f.puts "verify_api_cert    false"
          # f.puts "ssl_verify_mode    :verify_none"
        }
        if !File.exist?("#{chefdir}/knife.rb") or
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
      def self.saveKey(user, keyname, key)
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

      # Fetch the Chef server's metadata about an organization. Return nil if not found.
      # @param org [String]: The name of the organization
      # @return [Hash]
      def self.getOrg(org)
        begin
          Timeout::timeout(45) {
            response = chefAPI.get("organizations/#{org}")
            return response
          }
        rescue Timeout::Error
          MU.log "Timed out fetching Chef organization #{org}, retrying", MU::WARN
          retry
        end rescue Net::HTTPServerException
        return nil
      end

      # Fetch the Chef server's metadata about an organization. Return nil if not found.
      # @param org [String]: The name of the organization
      # @param fullname [String]: A more descriptive name for the organization.
      # @param add_users [Array<String>]: Users to add to the org.
      # @param remove_users [Array<String>]: Users to remove from the org.
      # @return [Boolean]
      def self.manageOrg(org, fullname: nil, add_users: [], remove_users: [])
        existing_org = getOrg(org)
        orgkey = nil
        add_users << "mu" if !add_users.include?("mu") and org != "mu"

        # This organization does not yet exist, create it
        if !existing_org
          begin
            org_data = {
              :name => org.dup,
              :full_name => fullname
            }
            Timeout::timeout(45) {
              response = chefAPI.post("organizations", org_data)
              MU.log "Created Chef organization #{org}", details: response
              orgkey = response["private_key"]

              add_users.each { |user|
                if getUser(user) == nil
                  MU.log "Requested addition of Chef user #{user} to organization #{org}, but no such user exists", MU::WARN
                  next
                end
                response = chefAPI.post("organizations/#{org}/association_requests", {:user => user})
                association_id = response["uri"].split("/").last
                response = chefAPI.put("users/#{user}/association_requests/#{association_id}", { :response => 'accept' })
                next if user == "mu"
                MU.log "Added user #{user} to Chef organization #{org}", details: response
              }
            }
            return orgkey
          rescue Net::HTTPServerException => e
            MU.log "Error setting up Chef organization #{org}: #{e.message}", MU::ERR, details: org_data
            return false
          rescue Timeout::Error
            MU.log "Timed out setting up Chef organization #{org}, retrying", MU::WARN
            retry
          end
        else
          begin
            Timeout::timeout(45) {
              add_users.each { |user|
                if getUser(user) == nil
                  MU.log "Requested addition of Chef user #{user} to organization #{org}, but no such user exists", MU::WARN
                  next
                end
                begin
                  response = chefAPI.post("organizations/#{org}/association_requests", {:user => user})
                rescue Net::HTTPServerException => e
                  if e.message == '409 "Conflict"'
                    next
                  else
                    raise e
                  end
                end
                association_id = response["uri"].split("/").last
                response = chefAPI.put("users/#{user}/association_requests/#{association_id}", { :response => 'accept' })
                next if user == "mu"
                MU.log "Added user #{user} to Chef organization #{org}", details: response
              }
              remove_users.each { |user|
                begin
                  chefAPI.delete("organizations/#{org}/users/#{user}")
                  MU.log "Removed Chef user #{user} from organization #{org}", MU::NOTICE
                rescue Net::HTTPServerException => e
                end
              }
            }
          rescue Timeout::Error
            MU.log "Timed out modifying Chef organization #{org}, retrying", MU::WARN
            retry
          end
        end
        return orgkey
      end

      # Call when creating or modifying a user. While Chef technically does
      # communicate with LDAP, it's only for the web UI, which we don't even use.
      # Keys still need to be managed, and sometimes the username can't even match
      # the LDAP one due to Chef's weird restrictions.
      def self.manageUser(chef_user, name: nil, email: nil, orgs: [], remove_orgs: [], admin: false, ldap_user: nil, pass: nil)
        orgs = [] if orgs.nil?
        remove_orgs = [] if remove_orgs.nil?

        # In this shining future, there are no situations where we will *not* have
        # an LDAP user to link to.
        ldap_user = chef_user.dup if ldap_user.nil?
        if chef_user.gsub!(/\./, "")
          MU.log "Stripped . from username to create Chef user #{chef_user}.\nSee: https://github.com/chef/chef-server/issues/557", MU::NOTICE
          orgs.delete(ldap_user)
        end

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

        MU::Master.setLocalDataPerms(ldap_user)

        first = last = nil
        if !name.nil?
          last = name.split(/\s+/).pop
          first = name.split(/\s+/).shift
        end
        mangled_email = email.dup

        ext = getUser(chef_user)

        if !ext
          if name.nil? or email.nil?
            MU.log "Error creating Chef user #{chef_user}: Must supply real name and email address", MU::ERR
            return false
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
              saveKey(ldap_user, "#{chef_user}.user.key", response["chef_key"]["private_key"])
              key = manageOrg(chef_user, fullname: "#{name}'s Chef Organization", add_users: [chef_user])
              if key
                saveKey(ldap_user, "#{chef_user}.org.key", key)
              end
              createUserKnifeCfg(ldap_user, chef_user)
              createUserClientCfg(ldap_user, chef_user)
            }
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
        # This user exists, so modify it
        else
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
                saveKey(ldap_user, "#{chef_user}.user.key", response["chef_key"]["private_key"])
              end
            }
            createUserKnifeCfg(ldap_user, chef_user)
            createUserClientCfg(ldap_user, chef_user)
            %{/bin/su "#{ldap_user}" -c "cd && /opt/chef/bin/knife ssl fetch"}
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
        end

        if ldap_user != chef_user
          File.open($MU_CFG['datadir']+"/users/#{ldap_user}/chef_user", File::CREAT|File::RDWR, 0640) { |f|
            f.puts chef_user
          }
        end
        orgs.each { |org|
          key = manageOrg(org, add_users: [chef_user])
          if key
            saveKey(ldap_user, "#{org}.org.key", key)
          end
        }
        remove_orgs.each { |org|
          manageOrg(org, remove_users: [chef_user])
        }

        # Meddling in the user's home directory
        # Make sure they'll trust the Chef server's SSL certificate

        MU::Master.setLocalDataPerms(ldap_user)
        true
      end

      # Mangle Chef's server config to speak to LDAP. Technically this only
      # impacts logins for their web UI, which we currently don't use.
      def self.configureChefForLDAP
        if $MU_CFG.has_key?("ldap")
          bind_creds = MU::Groomer::Chef.getSecret(vault: $MU_CFG["ldap"]["bind_creds"]["vault"], item: $MU_CFG["ldap"]["bind_creds"]["item"])
          vars = {
            "server_url" => $MU_CFG["public_address"],
            "ldap" => true,
            "base_dn" => $MU_CFG["ldap"]["base_dn"],
            "group_dn" => $MU_CFG["ldap"]["admin_group_dn"],
            "dc" => $MU_CFG["ldap"]["dcs"].first,
            "bind_dn" => bind_creds[$MU_CFG["ldap"]["bind_creds"]["username_field"]],
            "bind_pw" => bind_creds[$MU_CFG["ldap"]["bind_creds"]["password_field"]],
          }
          chef_cfgfile = "/etc/opscode/chef-server.rb"
          chef_tmpfile = "#{chef_cfgfile}.tmp.#{Process.pid}"
          File.open(chef_tmpfile, File::CREAT|File::RDWR, 0644) { |f|
            f.puts Erubis::Eruby.new(File.read("#{$MU_CFG['libdir']}/install/chef-server.rb.erb")).result(vars)
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
