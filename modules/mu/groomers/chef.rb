# Copyright:: Copyright (c) 2014 eGlobalTech, Inc., all rights reserved
#
# Licensed under the BSD-3 license (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License in the root of the project or at
#
#	  http://egt-labs.com/mu/LICENSE.html
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


module MU
  # Plugins under this namespace serve as interfaces to host configuration
  # management tools, like Chef or Puppet.
  class Groomer
    # Support for Chef as a host configuration management layer.
    class Chef

      # Wrapper class for temporary Exceptions. Gives our internals something
      # to inherit that will log a notice message appropriately before
      # bubbling up.
      class MuNoSuchSecret < StandardError;end

      Object.class_eval {
        def self.const_missing(symbol)
          if symbol.to_sym == :Chef or symbol.to_sym == :ChefVault
            MU::Groomer::Chef.loadChefLib
            return Object.const_get(symbol)
          end
        end
        def const_missing(symbol)
          if symbol.to_sym == :Chef or symbol.to_sym == :ChefVault
            MU::Groomer::Chef.loadChefLib(@server.deploy.mu_user, @server.deploy.environment)
            return Object.const_get(symbol)
          end
        end
      }

      @chefloaded = false
      @chefload_semaphore = Mutex.new
      # Autoload is too brain-damaged to get Chef's subclasses/submodules, so
      # implement our own lazy loading.
      def self.loadChefLib(user = MU.mu_user, env = "dev")
        @chefload_semaphore.synchronize {
          if !@chefloaded
            MU.log "Loading Chef libraries..."
            start = Time.now
            require 'chef'
            require 'chef/api_client_v1'
            require 'chef/knife'
            require 'chef/knife/ssh'
            require 'chef/knife/bootstrap'
            require 'chef/knife/bootstrap_windows_ssh'
            require 'chef/knife/node_delete'
            require 'chef/knife/client_delete'
            require 'chef/knife/data_bag_delete'
            require 'chef/knife/vault_delete'
            require 'chef/scan_access_control'
            require 'chef/file_access_control/unix'
            require 'chef-vault'
            require 'chef-vault/item'
            if File.exists?("#{Etc.getpwnam(user).dir}/.chef/knife.rb")
              MU.log "Loading Chef configuration from #{Etc.getpwnam(user).dir}/.chef/knife.rb", MU::DEBUG
              ::Chef::Config.from_file("#{Etc.getpwnam(user).dir}/.chef/knife.rb")
            end
            ::Chef::Config[:chef_server_url] = "https://#{MU.mu_public_addr}:7443/organizations/#{MU.chef_user}"
            ::Chef::Config[:environment] = env
            ::Chef::Config[:yes] = true
            @chefloaded = true
            MU.log "Chef libraries loaded (took #{(Time.now-start).to_s} seconds)"
          end
        }
      end

      @knife = "cd #{MU.myRoot} && env -i HOME=#{Etc.getpwnam(MU.mu_user).dir} #{MU.mu_env_vars} PATH=/opt/chef/embedded/bin:/usr/bin:/usr/sbin knife"
      # The canonical path to invoke Chef's *knife* utility with a clean environment.
      # @return [String]
      def self.knife;
        @knife;
      end

      attr_reader :knife

      @vault_opts = "--mode client -u #{MU.chef_user} -F json"
      # The canonical set of arguments for most `knife vault` commands
      # @return [String]
      def self.vault_opts;
        @vault_opts;
      end

      attr_reader :vault_opts

      @chefclient = "env -i HOME=#{Etc.getpwuid(Process.uid).dir} #{MU.mu_env_vars} PATH=/opt/chef/embedded/bin:/usr/bin:/usr/sbin chef-client"
      # The canonical path to invoke Chef's *chef-client* utility with a clean environment.
      # @return [String]
      def self.chefclient;
        @chefclient;
      end

      attr_reader :chefclient


      # @param node [MU::Cloud::Server]: The server object on which we'll be operating
      def initialize(node)
        @config = node.config
        @server = node
        if node.mu_name.nil? or node.mu_name.empty?
          raise MuError, "Cannot groom a server that doesn't tell me its mu_name"
        end
        @secrets_semaphore = Mutex.new
        @secrets_granted = {}
      end

      # Indicate whether our server has been bootstrapped with Chef
      def haveBootstrapped?
        self.class.loadChefLib
        MU.log "Chef config", MU::DEBUG, details: ::Chef::Config.inspect
        nodelist = ::Chef::Node.list()
        nodelist.has_key?(@server.mu_name)
      end

      # @param vault [String]: A repository of secrets to create/save into.
      # @param item [String]: The item within the repository to create/save.
      # @param data [Hash]: Data to save
      # @param permissions [String]: An implementation-specific string describing what node or nodes should have access to this secret.
      def self.saveSecret(vault: @server.mu_name, item: nil, data: nil, permissions: nil)
        loadChefLib
        if item.nil? or !item.is_a?(String)
          raise MuError, "item argument to saveSecret must be a String"
        end
        if data.nil? or !data.is_a?(Hash)
          raise MuError, "data argument to saveSecret must be a Hash"
        end

        cmd = "update"
        begin
          MU.log "Checking for existence of #{vault} #{item}", MU::DEBUG, details: caller
          ::ChefVault::Item.load(vault, item)
        rescue ::ChefVault::Exceptions::KeysNotFound
          cmd = "create"
        end
        if permissions
          MU.log "knife vault #{cmd} #{vault} #{item} --search #{permissions}"
          ::Chef::Knife.run(['vault', cmd, vault, item, JSON.generate(data).gsub(/'/, '\\1'), '--search', permissions])
        else
          MU.log "knife vault #{cmd} #{vault} #{item}"
          ::Chef::Knife.run(['vault', cmd, vault, item, JSON.generate(data).gsub(/'/, '\\1')])
        end
      end

      # see {MU::Groomer::Chef.saveSecret}
      def saveSecret(vault: @server.mu_name, item: nil, data: nil, permissions: "name:#{@server.mu_name}")
        self.class.saveSecret(vault: vault, item: item, data: data, permissions: permissions)
      end

      # Retrieve sensitive data, which hopefully we're storing and retrieving
      # in a secure fashion.
      # @param vault [String]: A repository of secrets to search
      # @param item [String]: The item within the repository to retrieve
      # @param field [String]: OPTIONAL - A specific field within the item to return.
      # @return [Hash]
      def self.getSecret(vault: nil, item: nil, field: nil)
        loadChefLib
        loaded = nil

        if !item.nil?
          begin
            loaded = ::ChefVault::Item.load(vault, item)
          rescue ::ChefVault::Exceptions::KeysNotFound => e
            raise MuNoSuchSecret, "Can't load the Chef Vault #{vault}:#{item}. Does it exist?"
          end
        else
          # If we didn't ask for a particular item, list what we have.
          begin
            loaded = ::Chef::DataBag.load(vault).keys.select { |k, v| !k.match(/_keys$/) }
          rescue Net::HTTPServerException
            raise MuNoSuchSecret, "Failed to retrieve Vault #{vault}"
          end
        end

        if loaded.nil?
          raise MuNoSuchSecret, "Failed to retrieve Vault #{vault}:#{item}"
        end

        if !field.nil?
          if loaded.has_key?(field)
            return loaded[field]
          else
            raise MuNoSuchSecret, "No such field in Vault #{vault}:#{item}"
          end
        else
          return loaded
        end
      end

      # see {MU::Groomer::Chef.getSecret}
      def getSecret(vault: nil, item: nil, field: nil)
        self.class.getSecret(vault: vault, item: item, field: field)
      end

      # Delete a Chef data bag / Vault
      # @param vault [String]: A repository of secrets to delete
      def self.deleteSecret(vault: nil, item: nil)
        loadChefLib
        raise MuError, "No vault specified, nothing to delete" if vault.nil?
        MU.log "Deleting #{vault}:#{item} from vaults"
        knife_db = nil
        knife_cmds = []
        if item.nil?
          knife_cmds << ::Chef::Knife::DataBagDelete.new(['data', 'bag', 'delete', vault])
        else
          knife_cmds << ::Chef::Knife::DataBagDelete.new(['data', 'bag', 'delete', vault, item])
          knife_cmds << ::Chef::Knife::DataBagDelete.new(['data', 'bag', 'delete', vault, item+"_keys"])
        end
        begin
          knife_cmds.each { |knife_db|
            knife_db.config[:yes] = true
            knife_db.run
          }
        rescue Net::HTTPServerException => e
          # We don't want to raise an error here. As an example we might be cleaning up a dead node in a server pool and this will then fail for no god reasons.
          MU.log "Tried to delete vault #{vault} but got #{e.inspect}, giving up", MU::ERR
        end
      end

      # see {MU::Groomer::Chef.deleteSecret}
      def deleteSecret(vault: nil)
        self.class.deleteSecret(vault: vault)
      end

      # Invoke the Chef client on the node at the other end of a provided SSH
      # session.
      # @param purpose [String] = A string describing the purpose of this client run.
      # @param max_retries [Integer] = The maximum number of attempts at a successful run to make before giving up.
      def run(purpose: "Chef run", update_runlist: true, max_retries: 5)
        self.class.loadChefLib
        if update_runlist and !@config['run_list'].nil?
          knifeAddToRunList(multiple: @config['run_list'])
        end

        if !@config['application_attributes'].nil?
          chef_node = ::Chef::Node.load(@server.mu_name)
          MU.log "Setting node:#{@server.mu_name} application_attributes", MU::DEBUG, details: @config['application_attributes']
          chef_node.normal.application_attributes = @config['application_attributes']
          chef_node.save
        end
        saveDeployData

        MU.log "Invoking Chef on #{@server.mu_name}: #{purpose}"
        retries = 0
        output = []
        error_signal = "CHEF EXITED BADLY: "+(0...25).map { ('a'..'z').to_a[rand(26)] }.join
        runstart = nil
        begin
          ssh = @server.getSSHSession(max_retries)
          cmd = nil
          if !@server.windows?
            if !@config["ssh_user"].nil? and !@config["ssh_user"].empty? and @config["ssh_user"] != "root"
              cmd = "sudo chef-client --color || echo #{error_signal}"
            else
              cmd = "chef-client --color || echo #{error_signal}"
            end
          else
            cmd = "$HOME/chef-client --color || echo #{error_signal}"
          end
          runstart = Time.new
          retval = ssh.exec!(cmd) { |ch, stream, data|
            puts data
            output << data
            raise MU::Groomer::RunError, output.grep(/ ERROR: /).last if data.match(/#{error_signal}/)
          }
        rescue RuntimeError, SystemCallError, Timeout::Error, SocketError, Errno::ECONNRESET, IOError, Net::SSH::Exception, MU::Groomer::RunError => e
          begin
            ssh.close if !ssh.nil?
          rescue Net::SSH::Exception, IOError => e
            if @server.windows?
              MU.log "Windows has probably closed the ssh session before we could. Waiting before trying again", MU::DEBUG
            else
              MU.log "ssh session to #{@server.mu_name} was closed unexpectedly, waiting before trying again", MU::NOTICE
            end
            sleep 10
          end

          if retries < max_retries
            retries += 1
            MU.log "#{@server.mu_name}: Chef run '#{purpose}' failed after #{Time.new - runstart} seconds, retrying (#{retries}/#{max_retries})", MU::WARN, details: e.inspect
            sleep 30
            retry
          else
            raise MU::Groomer::RunError, "#{@server.mu_name}: Chef run '#{purpose}' failed #{max_retries} times, last error was: #{e.message}"
          end
        end

        saveDeployData
      end

      # Make sure we've got a Splunk admin vault for any mu-splunk-servers to
      # use, and set it up if we don't.
      def splunkVaultInit
        self.class.loadChefLib
        begin
          loaded = ::ChefVault::Item.load("splunk", "admin_user")
        rescue ::ChefVault::Exceptions::KeysNotFound => e
          pw = Password.pronounceable(12..14)
          creds = {
            "username" => "admin",
            "password" => pw,
            "auth" => "admin:#{pw}"
          }
          saveSecret(
            vault: "splunk",
            item: "admin_user",
            data: creds,
            permissions: "role:mu-splunk-server"
          )
        end
      end

      # Expunge
      def preClean(leave_ours = false)
        remove_cmd = nil
        if !@server.windows?
          if @server.config['ssh_user'] == "root"
            remove_cmd = "rm -rf /var/chef/ /etc/chef /opt/chef/ /usr/bin/chef-* ; yum -y erase chef; apt-get -y remove chef ; touch /opt/mu_installed_chef"
          else
            remove_cmd = "sudo rm -rf /var/chef/ /etc/chef /opt/chef/ /usr/bin/chef-* ; yum -y erase chef; apt-get -y remove chef ; touch /opt/mu_installed_chef"
          end
          guardfile = "/opt/mu_installed_chef"
        else
          remove_cmd = "rm -rf /cygdrive/c/opscode /cygdrive/c/chef"
          guardfile = "/cygdrive/c/mu_installed_chef"
        end

        ssh = @server.getSSHSession(15)
        if leave_ours
          MU.log "Expunging pre-existing Chef install on #{@server.mu_name}, if we didn't create it", MU::NOTICE
          ssh.exec!(%Q{test -f #{guardfile} || (#{remove_cmd}) ; touch #{guardfile}})
        else
          MU.log "Expunging pre-existing Chef install on #{@server.mu_name}", MU::NOTICE
          ssh.exec!(remove_cmd)
        end

        ssh.close
      end

      # Bootstrap our server with Chef
      def bootstrap
        self.class.loadChefLib
        createGenericHostSSLCert
        if !@config['cleaned_chef']
          begin
            preClean(true)
          rescue RuntimeError => e
            MU.log e.inspect, MU::ERR
            sleep 10
            retry
          end
          @config['cleaned_chef'] = true
        end

        nat_ssh_key, nat_ssh_user, nat_ssh_host, canonical_addr, ssh_user, ssh_key_name = @server.getSSHConfig
        MU.log "Bootstrapping #{@server.mu_name} (#{canonical_addr}) with knife"

        run_list = ["role[mu-node]", "recipe[mu-tools::newclient]"]
        run_list << "recipe[mu-tools::updates]" if !@config['skipinitialupdates']

        json_attribs = {}
        if !@config['application_attributes'].nil?
          json_attribs['application_attributes'] = @config['application_attributes']
          json_attribs['skipinitialupdates'] = @config['skipinitialupdates']
        end

        if !@config['vault_access'].nil?
          vault_access = @config['vault_access']
        else
          vault_access = []
        end

        if !@server.windows?
          kb = ::Chef::Knife::Bootstrap.new([canonical_addr])
          kb.config[:use_sudo] = true
          kb.config[:distro] = 'chef-full'
        else
          kb = ::Chef::Knife::BootstrapWindowsSsh.new([canonical_addr])
          kb.config[:cygwin] = true
          kb.config[:distro] = 'windows-chef-client-msi'
          # kb.config[:node_ssl_verify_mode] = 'none'
          # kb.config[:node_verify_api_cert] = false
        end

        # XXX this seems to break Knife Bootstrap for the moment
        #			if vault_access.size > 0
        #				v = {}
        #				vault_access.each { |vault|
        #					v[vault['vault']] = [] if v[vault['vault']].nil?
        #					v[vault['vault']] << vault['item']
        #				}
        #				kb.config[:bootstrap_vault_json] = JSON.generate(v)
        #			end

        kb.config[:json_attribs] = JSON.generate(json_attribs) if json_attribs.size > 1
        kb.config[:run_list] = run_list
        kb.config[:ssh_user] = ssh_user
        kb.config[:forward_agent] = ssh_user
        kb.name_args = "#{canonical_addr}"
        kb.config[:chef_node_name] = @server.mu_name
        kb.config[:bootstrap_version] = MU.chefVersion
        # XXX key off of MU verbosity level
        kb.config[:log_level] = :debug
        kb.config[:identity_file] = "#{Etc.getpwuid(Process.uid).dir}/.ssh/#{ssh_key_name}"
        # kb.config[:ssh_gateway] = "#{nat_ssh_user}@#{nat_ssh_host}" if !nat_ssh_host.nil? # Breaking bootsrap
        # This defaults to localhost for some reason sometimes. Brute-force it.

        MU.log "Knife Bootstrap settings for #{@server.mu_name} (#{canonical_addr})", MU::NOTICE, details: kb.config

        retries = 0
        @server.windows? ? max_retries = 25 : max_retries = 10
        @server.windows? ? timeout = 720 : timeout = 300
        begin
          Timeout::timeout(timeout) {
            require 'chef'
            kb.run
          }
          # throws Net::HTTPServerException if we haven't really bootstrapped
          ::Chef::Node.load(@server.mu_name)
        rescue Net::SSH::Disconnect, SystemCallError, Timeout::Error, Errno::ECONNRESET, Errno::EHOSTUNREACH, Net::SSH::Proxy::ConnectError, SocketError, Net::SSH::Disconnect, Net::SSH::AuthenticationFailed, IOError, Net::HTTPServerException, SystemExit, Errno::ECONNREFUSED, Errno::EPIPE => e
          if retries < max_retries
            retries += 1
            MU.log "#{@server.mu_name}: Knife Bootstrap failed #{e.inspect}, retrying (#{retries} of #{max_retries})", MU::WARN, details: e.backtrace
            sleep 10*retries
            retry
          else
            raise MuError, "#{@server.mu_name}: Knife Bootstrap failed too many times with #{e.inspect}"
          end
        end

        # Now that we're done, remove one-shot bootstrap recipes from the
        # node's final run list
        ["mu-tools::newclient", "mu-tools::updates"].each { |recipe|
          begin
            ::Chef::Knife.run(['node', 'run_list', 'remove', @server.mu_name, "recipe[#{recipe}]"], {})
          rescue SystemExit => e
            MU.log "#{@server.mu_name}: Run list removal of recipe[#{recipe}] failed with #{e.inspect}", MU::WARN
          end
        }

        splunkVaultInit
        grantSecretAccess(@server.mu_name, "windows_credentials") if @server.windows?
        grantSecretAccess(@server.mu_name, "ssl_cert")

        # Making sure all Windows nodes get the mu-tools::windows-client recipe
        if @server.windows?
          knifeAddToRunList("recipe[mu-tools::windows-client]")
          run(purpose: "Base Windows configuration", update_runlist: false, max_retries: 20)
        end

        # This will deal with Active Directory integration.
        if !@config['active_directory'].nil?
          if @config['active_directory']['domain_operation'] == "join"
            knifeAddToRunList("recipe[mu-activedirectory::domain-node]")
            run(purpose: "Join Active Directory", update_runlist: false, max_retries: max_retries)
          elsif @config['active_directory']['domain_operation'] == "create"
            knifeAddToRunList("recipe[mu-activedirectory::domain]")
            run(purpose: "Create Active Directory Domain", update_runlist: false, max_retries: 15)
          elsif @config['active_directory']['domain_operation'] == "add_controller"
            knifeAddToRunList("recipe[mu-activedirectory::domain-controller]")
            run(purpose: "Add Domain Controller to Active Directory", update_runlist: false, max_retries: 15)
          end
        end

        if !@config['run_list'].nil?
          knifeAddToRunList(multiple: @config['run_list'])
        end

        saveDeployData
      end

      # Synchronize the deployment structure managed by {MU::MommaCat} to Chef,
      # so that nodes can access this metadata.
      # @return [Hash]: The data synchronized.
      def saveDeployData
        self.class.loadChefLib
        @server.describe(update_cache: true) # Make sure we're fresh
        saveChefMetadata
        begin
          chef_node = ::Chef::Node.load(@server.mu_name)

          # Our deploydata gets corrupted often with server pools, in this case the the deploy data structure of some nodes is corrupt the hashes can become too nested and also invalid.
          # When we try to merge this invalid structure with our chef node structure we get a 'stack level too deep' error.
          # The choice here is to either fail more gracefully or try to clean up our deployment data. This is an attempt to implement the second option
          nodes_to_delete = []
          node_class = nil
          if @server.deploy.deployment.has_key?('servers')
            @server.deploy.deployment['servers'].each_pair { |nodeclass, server_struct|
              node_class = nodeclass
              server_struct.each_pair { |name, server|
                if server.is_a?(Hash) && !server.has_key?('nodename')
                  MU.log "#{name} deploy data is corrupt, trying to delete section before merging deployment metadata", MU::ERR, details: server
                  nodes_to_delete << name
                end
              }
            }
          end

          if !nodes_to_delete.empty?
            nodes_to_delete.each { |name|
              @server.deploy.deployment['servers'][node_class].delete(name)
            }
          end

          if chef_node.normal.deployment != @server.deploy.deployment
            MU.log "Updating node: #{@server.mu_name} deployment attributes", details: @server.deploy.deployment
            chef_node.normal.deployment.merge!(@server.deploy.deployment)
            chef_node.save
          end
          return chef_node.deployment
        rescue Net::HTTPServerException => e
          MU.log "Attempted to save deployment to Chef node #{@server.mu_name} before it was bootstrapped.", MU::DEBUG
        end
      end

      # Expunge Chef resources associated with a node.
      # @param node [String]: The Mu name of the node in question.
      # @param vaults_to_clean [Array<Hash>]: Some vaults to expunge
      # @param noop [Boolean]: Skip actual deletion, just state what we'd do
      def self.cleanup(node, vaults_to_clean = [], noop = false)
        loadChefLib
        MU.log "Deleting Chef resources associated with #{node}"
        vaults_to_clean.each { |vault|
          MU::MommaCat.lock("vault-#{vault['vault']}", false, true)
          MU.log "knife vault remove #{vault['vault']} #{vault['item']} --search name:#{node}", MU::NOTICE
          ::Chef::Knife.run(['vault', 'remove', vault['vault'], vault['item'], "--search", "name:#{node}"]) if !noop
          MU::MommaCat.unlock("vault-#{vault['vault']}")
        }
        MU.log "knife node delete #{node}"
        if !noop
          knife_nd = ::Chef::Knife::NodeDelete.new(['node', 'delete', node])
          knife_nd.config[:yes] = true
          begin
            knife_nd.run
          rescue Net::HTTPServerException
          end
        end
        MU.log "knife client delete #{node}"
        if !noop
          knife_cd = ::Chef::Knife::ClientDelete.new(['client', 'delete', node])
          knife_cd.config[:yes] = true
          begin
            knife_cd.run
          rescue Net::HTTPServerException
          end
        end

        begin
          deleteSecret(vault: node) if !noop
        rescue MuNoSuchSecret
        end
        ["crt", "key", "csr"].each { |ext|
          if File.exists?("#{MU.mySSLDir}/#{node}.#{ext}")
            MU.log "Removing #{MU.mySSLDir}/#{node}.#{ext}"
            File.unlink("#{MU.mySSLDir}/#{node}.#{ext}") if !noop
          end
        }
      end

      # Allow a node access to a vault.
      # @param host [String]:
      # @param vault [String]:
      # @param item [String]:
      def self.grantSecretAccess(host, vault, item)
        loadChefLib
        MU::MommaCat.lock("vault-#{vault}", false, true)
        MU.log "Granting #{host} access to #{vault} #{item}"
        begin
          ::Chef::Knife.run(['vault', 'update', vault, item, "--search", "name:#{host}"])
        rescue Exception => e
          MU.log e.inspect, MU::ERR, details: caller
        end
        MU::MommaCat.unlock("vault-#{vault}", true)
      end

      private

      # Save common Mu attributes to this node's Chef node structure.
      def saveChefMetadata
        self.class.loadChefLib
        nat_ssh_key, nat_ssh_user, nat_ssh_host, canonical_addr, ssh_user, ssh_key_name = @server.getSSHConfig
        MU.log "Saving #{@server.mu_name} Chef artifacts"

        begin
          chef_node = ::Chef::Node.load(@server.mu_name)
        rescue Net::HTTPServerException
          raise MU::Groomer::RunError, "Couldn't load Chef node #{@server.mu_name}"
        end

        # Figure out what this node thinks its name is
        system_name = chef_node['fqdn'] if !chef_node['fqdn'].nil?
        MU.log "#{@server.mu_name} local name is #{system_name}", MU::DEBUG

        chef_node.normal.app = @config['application_cookbook'] if @config['application_cookbook'] != nil
        chef_node.normal.service_name = @config["name"]
        chef_node.normal.windows_admin_username = @config['windows_admin_username']
        chef_node.chef_environment = MU.environment.downcase
        if @server.config['cloud'] == "AWS"
          chef_node.normal.ec2 = MU.structToHash(@server.cloud_desc)
        end

        if @server.windows?
          chef_node.normal.windows_admin_username = @config['windows_admin_username']
          chef_node.normal.windows_auth_vault = @server.mu_name
          chef_node.normal.windows_auth_item = "windows_credentials"
          chef_node.normal.windows_auth_password_field = "password"
          chef_node.normal.windows_auth_username_field = "username"
          chef_node.normal.windows_ec2config_password_field = "ec2config_password"
          chef_node.normal.windows_ec2config_username_field = "ec2config_username"
          chef_node.normal.windows_sshd_password_field = "sshd_password"
          chef_node.normal.windows_sshd_username_field = "sshd_username"
        end

        # If AD integration has been requested for this node, give Chef what it'll need.
        if !@config['active_directory'].nil?
          chef_node.normal.ad.computer_name = @server.mu_windows_name
          chef_node.normal.ad.node_class = @config['name']
          chef_node.normal.ad.domain_name = @config['active_directory']['domain_name']
          chef_node.normal.ad.node_type = @config['active_directory']['node_type']
          chef_node.normal.ad.domain_operation = @config['active_directory']['domain_operation']
          chef_node.normal.ad.domain_controller_hostname = @config['active_directory']['domain_controller_hostname'] if @config['active_directory'].has_key?('domain_controller_hostname')
          chef_node.normal.ad.netbios_name = @config['active_directory']['short_domain_name']
          chef_node.normal.ad.computer_ou = @config['active_directory']['computer_ou'] if @config['active_directory'].has_key?('computer_ou')
          chef_node.normal.ad.dcs = @config['active_directory']['domain_controllers']
          chef_node.normal.ad.domain_join_vault = @config['active_directory']['domain_join_vault']['vault']
          chef_node.normal.ad.domain_join_item = @config['active_directory']['domain_join_vault']['item']
          chef_node.normal.ad.domain_join_username_field = @config['active_directory']['domain_join_vault']['username_field']
          chef_node.normal.ad.domain_join_password_field = @config['active_directory']['domain_join_vault']['password_field']
          chef_node.normal.ad.domain_admin_vault = @config['active_directory']['domain_admin_vault']['vault']
          chef_node.normal.ad.domain_admin_item = @config['active_directory']['domain_admin_vault']['item']
          chef_node.normal.ad.domain_admin_username_field = @config['active_directory']['domain_admin_vault']['username_field']
          chef_node.normal.ad.domain_admin_password_field = @config['active_directory']['domain_admin_vault']['password_field']
        end

        # Amazon-isms, possibly irrelevant
        awscli_region_widget = {
            "compile_time" => true,
            "config_profiles" => {
                "default" => {
                    "options" => {
                        "region" => @config['region']
                    }
                }
            }
        }
        chef_node.normal.awscli = awscli_region_widget

        if !@server.cloud.nil?
          chef_node.normal.cloudprovider = @server.cloud

          # XXX In AWS this is an OpenStruct-ish thing, but it may not be in
          # others.
          chef_node.normal[@server.cloud.to_sym] = MU.structToHash(@server.cloud_desc)
        end

        tags = MU::MommaCat.listStandardTags
        if !@config['tags'].nil?
          @config['tags'].each { |tag|
            tags[tag['key']] = tag['value']
          }
        end
        chef_node.normal.tags = tags
        chef_node.save

        # If we have a database make sure we grant access to that vault.
        # In some cases the cached getLitter response will not have all the resources in the deploy, so lets not use the cache.
        if @config.has_key?('dependencies')
          deploy = MU::MommaCat.getLitter(MU.deploy_id, use_cache: false)
          @config['dependencies'].each{ |dep|
            if dep['type'] == "database" && deploy.deployment.has_key?("databases")
                deploy.deployment["databases"][dep['name']].each { |name, database|
                grantSecretAccess(database['vault_name'], database['vault_item']) if database.has_key?("vault_name") && database.has_key?("vault_item")
              }
            end
          }
        end

        # Finally, grant us access to some pre-existing Vaults.
        if !@config['vault_access'].nil?
          @config['vault_access'].each { |vault|
            grantSecretAccess(vault['vault'], vault['item'])
          }
        end
      end

      def grantSecretAccess(vault, item)
        return if @secrets_granted["#{vault}:#{item}"] == item
        self.class.grantSecretAccess(@server.mu_name, vault, item)
        @secrets_granted["#{vault}:#{item}"] = item
      end

      def self.knifeCmd(cmd, showoutput = false)
        MU.log "knife #{cmd}", MU::NOTICE if showoutput
        output = `#{MU::Groomer::Chef.knife} #{cmd}`
        exitstatus = $?.exitstatus

        if showoutput
          puts output
          puts "Exit status: #{exitstatus}"
        end
        return [exitstatus, output]
      end

      def knifeCmd(cmd, showoutput = false)
        self.class.knifeCmd(cmd, showoutput)
      end

      def createGenericHostSSLCert
        nat_ssh_key, nat_ssh_user, nat_ssh_host, canonical_ip, ssh_user, ssh_key_name = @server.getSSHConfig
        # Manufacture a generic SSL certificate, signed by the Mu master, for
        # consumption by various node services (Apache, Splunk, etc).
        return if File.exists?("#{MU.mySSLDir}/#{@server.mu_name}.crt")
        MU.log "Creating self-signed service SSL certificate for #{@server.mu_name} (CN=#{canonical_ip})"

        # Create and save a key
        key = OpenSSL::PKey::RSA.new 4096
        if !Dir.exist?(MU.mySSLDir)
          Dir.mkdir(MU.mySSLDir, 0700)
        end

        open("#{MU.mySSLDir}/#{@server.mu_name}.key", 'w', 0600) { |io|
          io.write key.to_pem
        }

        # Create a certificate request for this node
        csr = OpenSSL::X509::Request.new
        csr.version = 0
        csr.subject = OpenSSL::X509::Name.parse "CN=#{canonical_ip}/O=Mu/C=US"
        csr.public_key = key.public_key
        open("#{MU.mySSLDir}/#{@server.mu_name}.csr", 'w', 0644) { |io|
          io.write csr.to_pem
        }


        if MU.chef_user == "mu"
          @server.deploy.signSSLCert("#{MU.mySSLDir}/#{@server.mu_name}.csr")
        else
          deploykey = OpenSSL::PKey::RSA.new(@server.deploy.public_key)
          deploysecret = Base64.urlsafe_encode64(deploykey.public_encrypt(@server.deploy.deploy_secret))
          res_type = "server"
          res_type = "server_pool" if !@config['basis'].nil?
          uri = URI("https://#{MU.mu_public_addr}:2260/")
          req = Net::HTTP::Post.new(uri)
          req.set_form_data(
              "mu_id" => MU.deploy_id,
              "mu_resource_name" => @config['name'],
              "mu_resource_type" => res_type,
              "mu_ssl_sign" => "#{MU.mySSLDir}/#{@server.mu_name}.csr",
              "mu_user" => MU.chef_user,
              "mu_deploy_secret" => deploysecret
          )
          http = Net::HTTP.new(uri.hostname, uri.port)
          http.ca_file = "/etc/pki/Mu_CA.pem" # XXX why no worky?
          http.use_ssl = true
          http.verify_mode = OpenSSL::SSL::VERIFY_NONE
          response = http.request(req)

          MU.log "Got error back on signing request for #{MU.mySSLDir}/#{@server.mu_name}.csr", MU::ERR if response.code != "200"
        end

        cert = OpenSSL::X509::Certificate.new File.read "#{MU.mySSLDir}/#{@server.mu_name}.crt"
        # Upload the certificate to a Chef Vault for this node
        certdata = {
            "data" => {
                "node.crt" => cert.to_pem.chomp!.gsub(/\n/, "\\n"),
                "node.key" => key.to_pem.chomp!.gsub(/\n/, "\\n")
            }
        }
        saveSecret(item: "ssl_cert", data: certdata, permissions: nil)

        # Any and all 'secrets' parameters should also be stuffed into our vault.
        saveSecret(item: "secrets", data: @config['secrets'], permissions: nil) if !@config['secrets'].nil?
      end

      # Add a role or recipe to a node. Optionally, throw a fit if it doesn't
      # exist.
      # @param rl_entry [String]: The run-list entry to add.
      # @param type [String]: One of *role* or *recipe*.
      # @param ignore_missing [Boolean]: If set to true, will merely warn about missing recipes/roles instead of throwing an exception.
      # @param multiple [Array<String>]: Add more than one run_list entry. Overrides rl_entry.
      # @return [void]
      def knifeAddToRunList(rl_entry = nil, type="role", ignore_missing: false, multiple: [])
        self.class.loadChefLib
        return if rl_entry.nil? and multiple.size == 0
        if multiple.size == 0
          multiple = [rl_entry]
        end
        multiple.each { |rl_entry|
          if !rl_entry.match(/^role|recipe\[/)
            rl_entry = "#{type}[#{rl_entry}]"
          end
        }

        if !ignore_missing
          role_list = nil
          recipe_list = nil
          missing = false
          multiple.each { |rl_entry|
            # Rather than argue about whether to expect a bare rl_entry name or
            # require rl_entry[rolename], let's just accomodate.
            if rl_entry.match(/^role\[(.+?)\]/)
              rl_entry_name = Regexp.last_match(1)
              if role_list.nil?
                query=%Q{#{MU::Groomer::Chef.knife} role list};
                role_list = %x{#{query}}
              end
              if !role_list.match(/(^|\n)#{rl_entry_name}($|\n)/)
                MU.log "Attempting to add non-existent #{rl_entry} to #{@server.mu_name}", MU::WARN
                missing = true
              end
            elsif rl_entry.match(/^recipe\[(.+?)\]/)
              rl_entry_name = Regexp.last_match(1)
              if recipe_list.nil?
                query=%Q{#{MU::Groomer::Chef.knife} recipe list};
                recipe_list = %x{#{query}}
              end
              if !recipe_list.match(/(^|\n)#{rl_entry_name}($|\n)/)
                MU.log "Attempting to add non-existent #{rl_entry} to #{@server.mu_name}", MU::WARN
                missing = true
              end
            end

            if missing and !ignore_missing
              raise MuError, "Can't continue with missing roles/recipes for #{@server.mu_name}"
            end
          }
        end

        rl_string = multiple.join(",")
        begin
          query=%Q{#{MU::Groomer::Chef.knife} node run_list add #{@server.mu_name} "#{rl_string}"};
          MU.log("Adding #{rl_string} to Chef run_list of #{@server.mu_name}")
          MU.log("Running #{query}", MU::DEBUG)
          output=%x{#{query}}
            # XXX rescue Exception is bad style
        rescue Exception => e
          raise MuError, "FAIL: #{MU::Groomer::Chef.knife} node run_list add #{@server.mu_name} \"#{rl_string}\": #{e.message} (output was #{output})"
        end
      end

    end # class Chef
  end # class Groomer
end # Module Mu
