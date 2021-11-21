# Copyright:: Copyright (c) 2014 eGlobalTech, Inc., all rights reserved
#
# Licensed under the BSD-3 license (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License in the root of the project or at
#
#    http://egt-labs.com/mu/LICENSE.html
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

      Object.class_eval {
        def self.const_missing(symbol)
          if symbol.to_sym == :Chef or symbol.to_sym == :ChefVault
            MU::Groomer::Chef.loadChefLib
            return Object.const_get(symbol)
          end
        end
        def const_missing(symbol)
          if symbol.to_sym == :Chef or symbol.to_sym == :ChefVault
            MU::Groomer::Chef.loadChefLib(@server.deploy.chef_user, @server.deploy.environment, @server.deploy.mu_user)
            return Object.const_get(symbol)
          end
        end
      }

      # Are the Chef libraries present and accounted for?
      def self.available?(windows = false)
        loadChefLib
        @chefloaded
      end

      @chefloaded = false
      @chefload_semaphore = Mutex.new
      # Autoload is too brain-damaged to get Chef's subclasses/submodules, so
      # implement our own lazy loading.
      def self.loadChefLib(user = MU.chef_user, env = "dev", mu_user = MU.mu_user)
        @chefload_semaphore.synchronize {
          if !@chefloaded
            MU.log "Loading Chef libraries as user #{user}...", MU::DEBUG
            start = Time.now
            # need to find which classes are actually needed instead of loading chef
            require 'chef'
            require 'chef/api_client_v1'
            require 'chef/knife'
            require 'chef/application/knife'
            require 'chef/knife/ssh'
            require 'mu/monkey_patches/chef_knife_ssh'
            require 'chef/knife/bootstrap'
            require 'chef/knife/bootstrap/train_connector'
            require 'chef/knife/bootstrap/chef_vault_handler'
            require 'chef/knife/bootstrap/client_builder'
            require 'chef/knife/node_delete'
            require 'chef/knife/client_delete'
            require 'chef/knife/data_bag_delete'
            require 'chef/knife/data_bag_show'
            require 'chef/knife/vault_delete'
            require 'chef/scan_access_control'
            require 'chef/file_access_control/unix'
            require 'chef-vault'
            require 'chef-vault/item'
            # XXX kludge to get at knife-windows when it's installed from 
            # a git repo and bundler sticks it somewhere in a corner
            $LOAD_PATH.each { |path|
              if path.match(/\/gems\/chef\-\d+\.\d+\.\d+\/lib$/)
                addpath = path.sub(/\/gems\/chef\-\d+\.\d+\.\d+\/lib$/, "")+"/bundler/gems"
                Dir.glob(addpath+"/knife-windows-*").each { |version|
                  $LOAD_PATH << version+"/lib"
                }
              end
            }
            require 'chef/knife/bootstrap_windows_winrm'
            require 'chef/knife/bootstrap_windows_ssh'
            ::Chef::Config[:chef_server_url] = "https://#{MU.mu_public_addr}:7443/organizations/#{user}"
            if File.exist?("#{Etc.getpwnam(mu_user).dir}/.chef/knife.rb")
              MU.log "Loading Chef configuration from #{Etc.getpwnam(mu_user).dir}/.chef/knife.rb", MU::DEBUG
              ::Chef::Config.from_file("#{Etc.getpwnam(mu_user).dir}/.chef/knife.rb")
            end
            ::Chef::Config[:environment] = env
            ::Chef::Config[:yes] = true
            if mu_user != "root"
              ::Chef::Config.trusted_certs_dir = "#{Etc.getpwnam(mu_user).dir}/.chef/trusted_certs"
            end

            @chefloaded = true
            MU.log "Chef libraries loaded (took #{(Time.now-start).to_s} seconds)", MU::DEBUG
          end
        }
      end

      @knife = "cd #{MU.myRoot} && env -i HOME=#{Etc.getpwnam(MU.mu_user).dir} PATH=/opt/chef/embedded/bin:/usr/bin:/usr/sbin knife"
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

      @chefclient = "env -i HOME=#{Etc.getpwuid(Process.uid).dir} PATH=/opt/chef/embedded/bin:/usr/bin:/usr/sbin chef-client"
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
          rescue ::ChefVault::Exceptions::KeysNotFound
            raise MuNoSuchSecret, "Can't load the Chef Vault #{vault}:#{item}. Does it exist? Chef user: #{MU.chef_user}"
          end
        else
          # If we didn't ask for a particular item, list what we have.
          begin
            loaded = ::Chef::DataBag.load(vault).keys.select { |k| !k.match(/_keys$/) }
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
      def getSecret(vault: @server.mu_name, item: nil, field: nil)
        self.class.getSecret(vault: vault, item: item, field: field)
      end

      # Delete a Chef data bag / Vault
      # @param vault [String]: A repository of secrets to delete
      def self.deleteSecret(vault: nil, item: nil)
        loadChefLib
        raise MuError, "No vault specified, nothing to delete" if vault.nil?
        MU.log "Deleting #{vault}:#{item} from vaults"

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
      # @param purpose [String]: A string describing the purpose of this client run.
      # @param max_retries [Integer]: The maximum number of attempts at a successful run to make before giving up.
      # @param output [Boolean]: Display Chef's regular (non-error) output to the console
      # @param override_runlist [String]: Use the specified run list instead of the node's configured list
      def run(purpose: "Chef run", update_runlist: true, max_retries: 5, output: true, override_runlist: nil, reboot_first_fail: false, timeout: 1800)
        self.class.loadChefLib
        if update_runlist and !@config['run_list'].nil?
          knifeAddToRunList(multiple: @config['run_list'])
        end

        chef_node = ::Chef::Node.load(@server.mu_name)
        if !@config['application_attributes'].nil?
          MU.log "Setting node:#{@server.mu_name} application_attributes", MU::DEBUG, details: @config['application_attributes']
          chef_node.normal['application_attributes'] = @config['application_attributes']
          chef_node.save
        end
        if !@config['groomer_variables'].nil?
          chef_node.normal['mu'] = @config['groomer_variables']
          chef_node.save
        end
        if @server.deploy.original_config.has_key?('parameters')
          MU.log "Setting node:#{@server.mu_name} parameters", MU::DEBUG, details: @server.deploy.original_config['parameters']
          chef_node.normal['mu_parameters'] = @server.deploy.original_config['parameters']
          chef_node.save
        end
        saveDeployData

        retries = 0
        try_upgrade = false
        output_lines = []
        error_signal = "CHEF EXITED BADLY: "+(0...25).map { ('a'..'z').to_a[rand(26)] }.join
        runstart = nil
        cmd = nil
        ssh = nil
        winrm = nil
        windows_try_ssh = false
        begin
          runstart = Time.new
          if !@server.windows? or windows_try_ssh
            MU.log "Invoking Chef over ssh on #{@server.mu_name}: #{purpose}"
            ssh = @server.getSSHSession(@server.windows? ? 1 : max_retries)
            if @server.windows?
              cmd = "chef-client.bat --color || echo #{error_signal}"
            elsif !@config["ssh_user"].nil? and !@config["ssh_user"].empty? and @config["ssh_user"] != "root"
              upgrade_cmd = try_upgrade ? "sudo curl -L https://chef.io/chef/install.sh | sudo version=#{MU.chefVersion} sh &&" : ""
              cmd = "#{upgrade_cmd} sudo chef-client --color || echo #{error_signal}"
            else
              upgrade_cmd = try_upgrade ? "curl -L https://chef.io/chef/install.sh | version=#{MU.chefVersion} sh &&" : ""
              cmd = "#{upgrade_cmd} chef-client --color || echo #{error_signal}"
            end
            Timeout::timeout(timeout) {
              ssh.exec!(cmd) { |_ch, _stream, data|
                extra_logfile = if Dir.exist?(@server.deploy.deploy_dir)
                  File.open(@server.deploy.deploy_dir+"/log", "a")
                end
                puts data
                output_lines << data
                extra_logfile.puts data.chomp if extra_logfile
                raise MU::Cloud::BootstrapTempFail if data.match(/REBOOT_SCHEDULED| WARN: Reboot requested:|Rebooting server at a recipe's request|Chef::Exceptions::Reboot/)
                if data.match(/#{error_signal}/)
                  error_msg = ""
                  clip = false
                  output_lines.each { |chunk|
                    chunk.split(/\n/).each { |line|
                      if !clip and line.match(/^========+/)
                        clip = true
                      elsif clip and line.match(/^Running handlers:/)
                        break
                      end

                      if clip and line.match(/[a-z0-9]/)
                        error_msg += line.gsub(/\e\[(\d+)m/, '')+"\n"
                      end
                    }
                  }
                  raise MU::Groomer::RunError, error_msg
                end
              }
            }
          else
            MU.log "Invoking Chef over WinRM on #{@server.mu_name}: #{purpose}"
            winrm = @server.getWinRMSession(haveBootstrapped? ? 2 : max_retries)
            if @server.windows? and @server.windowsRebootPending?(winrm)
              # Windows frequently gets stuck here
              if retries > 5
                @server.reboot(true)
              elsif retries > 3 
                @server.reboot
              end
              raise MU::Groomer::RunError, "#{@server.mu_name} has a pending reboot"
            end
            if try_upgrade
              pp winrm.run("Invoke-WebRequest -useb https://omnitruck.chef.io/install.ps1 | Invoke-Expression; Install-Project -version:#{MU.chefVersion} -download_directory:$HOME")
            end
            output_lines = []
            cmd = "c:/opscode/chef/bin/chef-client.bat --color"
            if override_runlist
              cmd = cmd + " -o '#{override_runlist}'"
            end
            resp = nil
            Timeout::timeout(timeout) {
              resp = winrm.run(cmd) do |stdout, stderr|
                if stdout
                  print stdout if output
                  output_lines << stdout
                end
                if stderr
                  MU.log stderr, MU::ERR
                  output_lines << stderr
                end
              end
            }

            if resp.exitcode == 1 and output_lines.join("\n").match(/Chef Client finished/)
              MU.log output_lines.last
            elsif resp.exitcode != 0
              raise MU::Cloud::BootstrapTempFail if resp.exitcode == 35 or output_lines.join("\n").match(/REBOOT_SCHEDULED| WARN: Reboot requested:|Rebooting server at a recipe's request|Chef::Exceptions::Reboot/)
              raise MU::Groomer::RunError, output_lines.slice(output_lines.length-50, output_lines.length).join("")
            end
          end
        rescue MU::Cloud::BootstrapTempFail
          MU.log "#{@server.mu_name} rebooting from Chef, waiting then resuming", MU::NOTICE

          sleep 30

          # weird failures seem common in govcloud
          if MU::Cloud::AWS.isGovCloud?(@config['region'])
            @server.reboot(true)
            sleep 30
          end
          retry
        rescue SystemExit, Timeout::Error, MU::Cloud::BootstrapTempFail, Net::HTTPServerException, HTTPClient::ConnectTimeoutError, WinRM::WinRMError, Net::SSH::AuthenticationFailed, Net::SSH::Disconnect, Net::SSH::ConnectionTimeout, Net::SSH::Proxy::ConnectError, Net::SSH::Exception, Errno::ECONNRESET, Errno::EHOSTUNREACH, Errno::ECONNREFUSED, Errno::EPIPE, SocketError, IOError => e
          begin
            ssh.close if !ssh.nil?
          rescue Net::SSH::Exception, IOError => e
            if @server.windows?
              MU.log "Windows has probably closed the ssh session before we could. Waiting before trying again", MU::DEBUG
            else
              MU.log "ssh session to #{@server.mu_name} was closed unexpectedly, waiting before trying again", MU::NOTICE
            end
            sleep 10
          rescue StandardError => e
            MU.log "Error I don't recognize closing ssh tunnel", MU::WARN, details: e.inspect
          end
          if e.instance_of?(MU::Groomer::RunError) and retries == 0 and max_retries > 1 and purpose != "Base Windows configuration"
            MU.log "Got a run error, will attempt to install/update Chef Client on next attempt", MU::NOTICE
            try_upgrade = true
          else
            try_upgrade = false
          end

          if e.is_a?(MU::Groomer::RunError)
            if reboot_first_fail
              try_upgrade = true
              begin
                preClean(true) # drop any Chef install that's not ours
                @server.reboot # try gently rebooting the thing
              rescue StandardError => e # it's ok to fail here (and to ignore failure)
                MU.log "preclean err #{e.inspect}", MU::ERR
              end
              reboot_first_fail = false
            end
          end

          if retries < max_retries
            retries += 1
            MU.log "#{@server.mu_name}: Chef run '#{purpose}' failed after #{Time.new - runstart} seconds, retrying (#{retries}/#{max_retries})", MU::WARN, details: e.message.dup
#            if purpose != "Base Windows configuration"
#              windows_try_ssh = !windows_try_ssh
#            end
            if e.is_a?(WinRM::WinRMError)
              if @server.windows? and retries >= 3 and retries % 3 == 0
                # Mix in a hard reboot if WinRM isn't answering
                @server.reboot(true)
              end
            end
            sleep 30
            retry
          else
            @server.deploy.sendAdminSlack("Chef run '#{purpose}' failed on `#{@server.mu_name}` :crying_cat_face:", msg: e.message)
            raise MU::Groomer::RunError, "#{@server.mu_name}: Chef run '#{purpose}' failed #{max_retries} times, last error was: #{e.message}"
          end
        rescue StandardError => e
          @server.deploy.sendAdminSlack("Chef run '#{purpose}' failed on `#{@server.mu_name}` :crying_cat_face:", msg: e.inspect)
          raise MU::Groomer::RunError, "Caught unexpected #{e.inspect} on #{@server.mu_name} in @groomer.run at #{e.backtrace[0]}"

        end

        saveDeployData
      end

      # Make sure we've got a Splunk admin vault for any mu-splunk-servers to
      # use, and set it up if we don't.
      def splunkVaultInit
        self.class.loadChefLib
        begin
          ::ChefVault::Item.load("splunk", "admin_user")
        rescue ::ChefVault::Exceptions::KeysNotFound
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
            remove_cmd = "rm -rf /var/chef/ /etc/chef /opt/chef/ /usr/bin/chef-* ; yum -y erase chef ; rpm -e chef; apt-get -y remove chef ; touch /opt/mu_installed_chef"
          else
            remove_cmd = "sudo yum -y erase chef ; sudo rpm -e chef ; sudo rm -rf /var/chef/ /etc/chef /opt/chef/ /usr/bin/chef-* ; sudo apt-get -y remove chef ; sudo touch /opt/mu_installed_chef"
          end
          guardfile = "/opt/mu_installed_chef"

          retries = 0
          begin
            ssh = @server.getSSHSession(25)
            Timeout::timeout(60) {
              if leave_ours
                MU.log "Expunging pre-existing Chef install on #{@server.mu_name}, if we didn't create it", MU::NOTICE
                begin 
                  ssh.exec!(%Q{test -f #{guardfile} || (#{remove_cmd}) ; touch #{guardfile}})
                rescue IOError => e
                  # TO DO - retry this in a cleaner way
                  MU.log "Got #{e.inspect} while trying to clean up chef, retrying", MU::NOTICE, details: %Q{test -f #{guardfile} || (#{remove_cmd}) ; touch #{guardfile}}
                  ssh = @server.getSSHSession(15)
                  ssh.exec!(%Q{test -f #{guardfile} || (#{remove_cmd}) ; touch #{guardfile}})
                end
              else
                MU.log "Expunging pre-existing Chef install on #{@server.mu_name}", MU::NOTICE
                ssh.exec!(remove_cmd)
              end
            }
          rescue Timeout::Error
            if retries < 5
              retries += 1
              sleep 5
              retry
            else
              raise MuError, "Failed to preClean #{@server.mu_name} after repeated timeouts"
            end
          end
  
          ssh.close
        else
          remove_cmd = %Q{
            $uninstall_string = (Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | Where-Object {$_.DisplayName -like "chef client*"}).UninstallString
            if($uninstall_string){
              $uninstall_string = ($uninstall_string -Replace "msiexec.exe","" -Replace "/I","" -Replace "/X","").Trim()
              $($uninstall_string -Replace '[\\s\\t]+', ' ').Split() | ForEach {
                start-process "msiexec.exe" -arg "/X $_ /qn" -Wait
              }
            }
            Remove-Item c:/chef/ -Force -Recurse -ErrorAction Continue
            Remove-Item c:/opscode/ -Force -Recurse -ErrorAction Continue
            Remove-Item C:/Users/ADMINI~1/AppData/Local/Temp/bootstrap*.bat -Force -Recurse -ErrorAction Continue
            Remove-Item C:/Users/ADMINI~1/AppData/Local/Temp/chef-* -Force -Recurse -ErrorAction Continue
          }
          shell = @server.getWinRMSession(15)
          removechef = true
          if leave_ours
            resp = shell.run("Test-Path c:/mu_installed_chef")
            if resp.stdout.chomp == "True"
              MU.log "Found existing Chef installation created by Mu, leaving it alone"
              removechef = false
            end
          end

#          remove_cmd = %Q{$my_chef = (Get-ItemProperty $location | Where-Object {$_.DisplayName -like "chef client*"}).DisplayName
          if removechef
            MU.log "Expunging pre-existing Chef install on #{@server.mu_name}", MU::NOTICE, details: remove_cmd
#            pp shell.run(remove_cmd)
          end
        end
      end

      # Forcibly (re)install Chef. Useful for upgrading or overwriting a
      # broken existing install.
      def reinstall
        try_winrm = false
        if !@server.windows?
          cmd = %Q{curl -LO https://omnitruck.chef.io/install.sh && sudo bash ./install.sh -v #{MU.chefVersion} && rm install.sh}
        else
          try_winrm = true
          cmd = %Q{Invoke-WebRequest -useb https://omnitruck.chef.io/install.ps1 | Invoke-Expression; Install-Project -version:#{MU.chefVersion} -download_directory:$HOME}
        end

        if try_winrm
          begin
            MU.log "Attempting Chef upgrade via WinRM on #{@server.mu_name}", MU::NOTICE, details: cmd
            winrm = @server.getWinRMSession(1, 30, winrm_retries: 2)
            pp winrm.run(cmd)
            return
          rescue SystemExit, Timeout::Error, MU::Cloud::BootstrapTempFail, MU::MuError, Net::HTTPServerException, HTTPClient::ConnectTimeoutError, WinRM::WinRMError, Net::SSH::AuthenticationFailed, Net::SSH::Disconnect, Net::SSH::ConnectionTimeout, Net::SSH::Proxy::ConnectError, Net::SSH::Exception, Errno::ECONNRESET, Errno::EHOSTUNREACH, Errno::ECONNREFUSED, Errno::EPIPE, SocketError, IOError
            MU.log "WinRM failure attempting Chef upgrade on #{@server.mu_name}, will fall back to ssh", MU::WARN
            cmd = %Q{powershell.exe -inputformat none -noprofile "#{cmd}"}
          end
        end

        MU.log "Attempting Chef upgrade via ssh on #{@server.mu_name}", MU::NOTICE, details: cmd
        ssh = @server.getSSHSession(1)
        ssh.exec!(cmd) { |_ch, _stream, data|
          puts data
        }
      end

      # Bootstrap our server with Chef
      def bootstrap
        self.class.loadChefLib
        stashHostSSLCertSecret
        splunkVaultInit
        if !@config['cleaned_chef']
          begin
            leave_ours = @config['scrub_groomer'] ? false : true
            preClean(leave_ours)
          rescue RuntimeError => e
            MU.log e.inspect, MU::ERR
            sleep 10
            retry
          end
          @config['cleaned_chef'] = true
        end

        _nat_ssh_key, _nat_ssh_user, _nat_ssh_host, canonical_addr, ssh_user, ssh_key_name = @server.getSSHConfig

        MU.log "Bootstrapping #{@server.mu_name} (#{canonical_addr}) with knife"

        run_list = ["recipe[mu-tools::newclient]"]
        run_list << "mu-tools::gcloud" if @server.cloud == "Google" or @server.config['cloud'] == "Google"

        json_attribs = {}
        if !@config['application_attributes'].nil?
          json_attribs['application_attributes'] = @config['application_attributes']
          json_attribs['skipinitialupdates'] = @config['skipinitialupdates']
        end

# XXX this seems to break Knife Bootstrap
#        vault_access = if !@config['vault_access'].nil?
#          @config['vault_access']
#        else
#          []
#        end

        @server.windows? ? max_retries = 25 : max_retries = 10
        @server.windows? ? timeout = 1800 : timeout = 300
        retries = 0
        begin
          load MU.myRoot+'/modules/mu/monkey_patches/chef_knife_ssh.rb'
          if !@server.windows?
            kb = ::Chef::Knife::Bootstrap.new([canonical_addr])
            kb.config[:use_sudo] = true
            kb.name_args = "#{canonical_addr}"
            kb.config[:distro] = 'chef-full'
            kb.config[:ssh_user] = ssh_user
            kb.config[:ssh_verify_host_key] = :accept_new
            kb.config[:forward_agent] = ssh_user
            kb.config[:identity_file] = "#{Etc.getpwuid(Process.uid).dir}/.ssh/#{ssh_key_name}"
            kb.config[:ssh_identity_file] = "#{Etc.getpwuid(Process.uid).dir}/.ssh/#{ssh_key_name}"
          else
            kb = ::Chef::Knife::BootstrapWindowsWinrm.new([@server.mu_name])
            kb.name_args = [@server.mu_name]
            kb.config[:manual] = true
            kb.config[:winrm_transport] = :ssl
            kb.config[:winrm_port] = 5986
            kb.config[:session_timeout] = timeout
            kb.config[:operation_timeout] = timeout
#            kb.config[:bootstrap_curl_options] = ""
            if retries % 2 == 0
              kb.config[:host] = canonical_addr
              kb.config[:winrm_authentication_protocol] = :basic
              kb.config[:winrm_user] = @server.config['windows_admin_username']
              kb.config[:winrm_password] = @server.getWindowsAdminPassword
            else
              kb.config[:host] = @server.mu_name
              kb.config[:winrm_authentication_protocol] = :cert
              kb.config[:winrm_client_cert] = "#{MU.mySSLDir}/#{@server.mu_name}-winrm.crt"
              kb.config[:winrm_client_key] = "#{MU.mySSLDir}/#{@server.mu_name}-winrm.key"
            end
#          kb.config[:ca_trust_file] = "#{MU.mySSLDir}/Mu_CA.pem"
            # XXX ca_trust_file doesn't work for some reason, so we have to set the below for now
            kb.config[:winrm_ssl_verify_mode] = :verify_none
            kb.config[:msi_url] = "https://www.chef.io/chef/download?p=windows&pv=2012&m=x86_64&v=#{MU.chefVersion}"
          end

          # XXX this seems to break Knife Bootstrap
          #      if vault_access.size > 0
          #        v = {}
          #        vault_access.each { |vault|
          #          v[vault['vault']] = [] if v[vault['vault']].nil?
          #          v[vault['vault']] << vault['item']
          #        }
          #        kb.config[:bootstrap_vault_json] = JSON.generate(v)
          #      end

          kb.config[:json_attribs] = JSON.generate(json_attribs) if json_attribs.size > 1
          kb.config[:run_list] = run_list
          kb.config[:chef_node_name] = @server.mu_name
          kb.config[:bootstrap_product] = "chef"
          kb.config[:bootstrap_version] = MU.chefVersion
          kb.config[:channel] = "stable"
          # XXX key off of MU verbosity level
          kb.config[:log_level] = :debug
          # kb.config[:ssh_gateway] = "#{nat_ssh_user}@#{nat_ssh_host}" if !nat_ssh_host.nil? # Breaking bootsrap

          MU.log "Knife Bootstrap settings for #{@server.mu_name} (#{canonical_addr}), timeout set to #{timeout.to_s}", MU::NOTICE, details: kb.config
          if @server.windows? and @server.windowsRebootPending?
            raise MU::Cloud::BootstrapTempFail, "#{@server.mu_name} has a pending reboot"
          end
          Timeout::timeout(timeout) {
            MU::Cloud.handleNetSSHExceptions
            kb.run
          }
          # throws Net::HTTPServerException if we haven't really bootstrapped
          ::Chef::Node.load(@server.mu_name)
        rescue SystemExit, Timeout::Error, MU::Cloud::BootstrapTempFail, Net::HTTPServerException, HTTPClient::ConnectTimeoutError, WinRM::WinRMError, Net::SSH::AuthenticationFailed, Net::SSH::Disconnect, Net::SSH::ConnectionTimeout, Net::SSH::Proxy::ConnectError, Net::SSH::Exception, Errno::ECONNRESET, Errno::EHOSTUNREACH, Errno::ECONNREFUSED, Errno::EPIPE, SocketError, IOError => e
          if retries < max_retries
            retries += 1
            # Bad Chef installs are possible culprits of bootstrap failures, so
            # try scrubbing them when that happens.
            # On Windows, even a fresh install comes up screwy disturbingly
            # often, so we let it start over from scratch if needed. Except for
            # the first attempt, which usually fails due to WinRM funk.
            if !e.is_a?(MU::Cloud::BootstrapTempFail) and
               !(e.is_a?(WinRM::WinRMError) and @config['forced_preclean']) and
               !@config['forced_preclean']
              begin
                preClean(false) # it's ok for this to fail
              rescue StandardError => e
              end
              MU::Groomer::Chef.purge(@server.mu_name, nodeonly: true)
              @config['forced_preclean'] = true
              @server.reboot if @server.windows? # *sigh*
            end
            MU.log "#{@server.mu_name}: Knife Bootstrap failed #{e.inspect}, retrying in #{(10*retries).to_s}s (#{retries} of #{max_retries})", MU::WARN, details: e.backtrace
            sleep 10*retries
            retry
          else
            raise MuError, "#{@server.mu_name}: Knife Bootstrap failed too many times with #{e.inspect}"
          end
        rescue StandardError => e
MU.log e.inspect, MU::ERR, details: e.backtrace
sleep 10*retries
retry
        end


        # Now that we're done, remove one-shot bootstrap recipes from the
        # node's final run list
        ["mu-tools::newclient"].each { |recipe|
          begin
            ::Chef::Knife.run(['node', 'run_list', 'remove', @server.mu_name, "recipe[#{recipe}]"], {})
          rescue SystemExit => e
            MU.log "#{@server.mu_name}: Run list removal of recipe[#{recipe}] failed with #{e.inspect}", MU::WARN
          end
        }
        knifeAddToRunList("role[mu-node]")
        knifeAddToRunList("recipe[mu-tools::selinux]")

        grantSecretAccess(@server.mu_name, "windows_credentials") if @server.windows?
        grantSecretAccess(@server.mu_name, "ssl_cert")

        saveChefMetadata
        knifeAddToRunList("recipe[mu-tools::updates]") if !@config['skipinitialupdates']
        # Making sure all Windows nodes get the mu-tools::windows-client recipe
        if @server.windows?
          knifeAddToRunList("recipe[mu-tools::windows-client]")
          run(purpose: "Base Windows configuration", update_runlist: false, max_retries: 20)
        elsif !@config['skipinitialupdates']
          run(purpose: "Base configuration", update_runlist: false, max_retries: 20)
        end
        ::Chef::Knife.run(['node', 'run_list', 'remove', @server.mu_name, "recipe[mu-tools::updates]"], {}) if !@config['skipinitialupdates']
        ::Chef::Knife.run(['node', 'run_list', 'remove', @server.mu_name, "recipe[mu-tools::selinux]"], {})

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
        if !haveBootstrapped?
          MU.log "saveDeployData invoked on #{@server.to_s} before Chef has been bootstrapped!", MU::WARN, details: caller
          return
        end

        @server.describe
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

          if !@server.deploy.deployment.nil? and 
             (chef_node.normal['deployment'].nil? or 
               (chef_node.normal['deployment'].to_h <=> @server.deploy.deployment) != 0
             )
            MU.log "Updating node: #{@server.mu_name} deployment attributes", details: @server.deploy.deployment
            chef_node.normal['deployment'].merge!(@server.deploy.deployment)
            chef_node.save
          end
          return chef_node['deployment']
        rescue Net::HTTPServerException
          MU.log "Attempted to save deployment to Chef node #{@server.mu_name} before it was bootstrapped.", MU::DEBUG
        end
      end

      # Purge Chef resources matching a particular deploy
      # @param deploy_id [String]
      # @param noop [Boolean]
      def self.cleanup(deploy_id, noop = false)
        return nil if deploy_id.nil? or deploy_id.empty?
        begin
          if File.exist?(Etc.getpwuid(Process.uid).dir+"/.chef/knife.rb")
            ::Chef::Config.from_file(Etc.getpwuid(Process.uid).dir+"/.chef/knife.rb")
          end
          deadnodes = []
          ::Chef::Config[:environment] ||= MU.environment
          q = ::Chef::Search::Query.new
          begin
            q.search("node", "tags_MU-ID:#{deploy_id}").each { |item|
              next if item.is_a?(Integer)
              item.each { |node|
                deadnodes << node.name
              }
            }
          rescue Net::HTTPServerException
          end

          begin
            q.search("node", "name:#{deploy_id}-*").each { |item|
              next if item.is_a?(Integer)
              item.each { |node|
                deadnodes << node.name
              }
            }
          rescue Net::HTTPServerException
          end
          MU.log "Missed some Chef resources in node cleanup, purging now", MU::NOTICE if deadnodes.size > 0
          deadnodes.uniq.each { |node|
            MU::Groomer::Chef.purge(node, [], noop)
          }
        rescue LoadError
        end

      end

      # Expunge Chef resources associated with a node.
      # @param node [String]: The Mu name of the node in question.
      # @param vaults_to_clean [Array<Hash>]: Some vaults to expunge
      # @param noop [Boolean]: Skip actual deletion, just state what we'd do
      # @param nodeonly [Boolean]: Just delete the node and its keys, but leave other artifacts
      def self.purge(node, vaults_to_clean = [], noop = false, nodeonly: false)
        loadChefLib
        MU.log "Deleting Chef resources associated with #{node}"
        if !nodeonly
          vaults_to_clean.each { |vault|
            MU::MommaCat.lock("vault-#{vault['vault']}", false, true)
            MU.log "knife vault remove #{vault['vault']} #{vault['item']} --search name:#{node}", MU::NOTICE
            begin
              ::Chef::Knife.run(['vault', 'remove', vault['vault'], vault['item'], "--search", "name:#{node}"]) if !noop
            rescue StandardError => e
              MU.log "Error removing vault access for #{node} from #{vault['vault']} #{vault['item']}", MU::ERR, details: e.inspect
            end
            MU::MommaCat.unlock("vault-#{vault['vault']}")
          }
        end
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
        MU.log "knife data bag delete #{node}"
        if !noop
          knife_cd = ::Chef::Knife::ClientDelete.new(['data', 'bag', 'delete', node])
          knife_cd.config[:yes] = true
          begin
            knife_cd.run
          rescue Net::HTTPServerException
          end
        end

        return if nodeonly

        vaults_to_clean.each { |vault|
          MU::MommaCat.lock("vault-#{vault['vault']}", false, true)
          MU.log "Purging unknown clients from #{vault['vault']} #{vault['item']}", MU::DEBUG
          output = %x{#{@knife} data bag show "#{vault['vault']}" "#{vault['item']}_keys" --format json}
          # This is an ugly workaround for --clean-unknown-clients, which in
          # fact cleans known clients.
          if output
            begin
              vault_cfg = JSON.parse(output)
              if vault_cfg['clients']
                searchstr = vault_cfg['clients'].map { |c| "name:"+c }.join(" OR ")
                MU.log "Preserving client list for vault #{vault['vault']} #{vault['item']}", MU::DEBUG, details: vault_cfg['clients']
                if !noop
                  ::Chef::Knife.run(['vault', 'rotate', 'keys', vault['vault'], vault['item'], "--clean-unknown-clients"])
                  ::Chef::Knife.run(['vault', 'update', vault['vault'], vault['item'], "--search", searchstr])
                  ::Chef::Knife.run(['vault', 'refresh', vault['vault'], vault['item']])
                end
              end
            rescue JSON::ParserError
              MU.log "Error parsing JSON from data bag #{vault['vault']} #{vault['item']}_keys, skipping vault client cleanse", MU::WARN
            end
          end
          MU::MommaCat.unlock("vault-#{vault['vault']}")
        }

        begin
          deleteSecret(vault: node) if !noop
        rescue MuNoSuchSecret
        end
        ["crt", "key", "csr"].each { |ext|
          if File.exist?("#{MU.mySSLDir}/#{node}.#{ext}")
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
          ::Chef::Knife.run(['vault', 'update', vault, item, "--clients", "#{host}"])
        rescue StandardError => e
          MU.log e.inspect, MU::ERR, details: caller
        end
        MU::MommaCat.unlock("vault-#{vault}", true)
      end

      # Execute a +knife+ command, and return its exit status and output
      # @param cmd [String]: The knife subcommand to run, such as +vault list+
      # @param showoutput [String]: Print the results to stdout
      # @return [Array<Integer,String>]
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

      private

      # Save common Mu attributes to this node's Chef node structure.
      def saveChefMetadata
        self.class.loadChefLib
        @server.getSSHConfig # why though
        MU.log "Saving #{@server.mu_name} Chef artifacts"

        begin
          chef_node = ::Chef::Node.load(@server.mu_name)
        rescue Net::HTTPServerException
          @server.deploy.sendAdminSlack("Couldn't load Chef metadata on `#{@server.mu_name}` :crying_cat_face:")
          raise MU::Groomer::RunError, "Couldn't load Chef node #{@server.mu_name}"
        end

        # Figure out what this node thinks its name is
        system_name = chef_node['fqdn'] if !chef_node['fqdn'].nil?
        MU.log "#{@server.mu_name} local name is #{system_name}", MU::DEBUG

        chef_node.normal.app = @config['application_cookbook'] if !@config['application_cookbook'].nil?
        chef_node.normal["service_name"] = @config["name"]
        chef_node.normal["credentials"] = @config["credentials"]
        chef_node.normal["windows_admin_username"] = @config['windows_admin_username']
        chef_node.chef_environment = MU.environment.downcase
        if @server.config['cloud'] == "AWS"
          chef_node.normal["ec2"] = MU.structToHash(@server.cloud_desc)
        end

        if @server.windows?
          chef_node.normal['windows_admin_username'] = @config['windows_admin_username']
          chef_node.normal['windows_auth_vault'] = @server.mu_name
          chef_node.normal['windows_auth_item'] = "windows_credentials"
          chef_node.normal['windows_auth_password_field'] = "password"
          chef_node.normal['windows_auth_username_field'] = "username"
          chef_node.normal['windows_ec2config_password_field'] = "ec2config_password"
          chef_node.normal['windows_ec2config_username_field'] = "ec2config_username"
          chef_node.normal['windows_sshd_password_field'] = "sshd_password"
          chef_node.normal['windows_sshd_username_field'] = "sshd_username"
        end

        # If AD integration has been requested for this node, give Chef what it'll need.
        if !@config['active_directory'].nil?
          chef_node.normal['ad']['computer_name'] = @server.mu_windows_name
          chef_node.normal['ad']['node_class'] = @config['name']
          chef_node.normal['ad']['domain_name'] = @config['active_directory']['domain_name']
          chef_node.normal['ad']['node_type'] = @config['active_directory']['node_type']
          chef_node.normal['ad']['domain_operation'] = @config['active_directory']['domain_operation']
          chef_node.normal['ad']['domain_controller_hostname'] = @config['active_directory']['domain_controller_hostname'] if @config['active_directory'].has_key?('domain_controller_hostname')
          chef_node.normal['ad']['netbios_name'] = @config['active_directory']['short_domain_name']
          chef_node.normal['ad']['computer_ou'] = @config['active_directory']['computer_ou'] if @config['active_directory'].has_key?('computer_ou')
          chef_node.normal['ad']['domain_sid'] = @config['active_directory']['domain_sid'] if @config['active_directory'].has_key?('domain_sid')
          chef_node.normal['ad']['dcs'] = @config['active_directory']['domain_controllers']
          chef_node.normal['ad']['domain_join_vault'] = @config['active_directory']['domain_join_vault']['vault']
          chef_node.normal['ad']['domain_join_item'] = @config['active_directory']['domain_join_vault']['item']
          chef_node.normal['ad']['domain_join_username_field'] = @config['active_directory']['domain_join_vault']['username_field']
          chef_node.normal['ad']['domain_join_password_field'] = @config['active_directory']['domain_join_vault']['password_field']
          chef_node.normal['ad']['domain_admin_vault'] = @config['active_directory']['domain_admin_vault']['vault']
          chef_node.normal['ad']['domain_admin_item'] = @config['active_directory']['domain_admin_vault']['item']
          chef_node.normal['ad']['domain_admin_username_field'] = @config['active_directory']['domain_admin_vault']['username_field']
          chef_node.normal['ad']['domain_admin_password_field'] = @config['active_directory']['domain_admin_vault']['password_field']
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
        chef_node.normal['awscli'] = awscli_region_widget

        if !@server.cloud.nil?
          chef_node.normal['cloudprovider'] = @server.cloud

          # XXX In AWS this is an OpenStruct-ish thing, but it may not be in
          # others.
          chef_node.normal[@server.cloud.to_sym] = MU.structToHash(@server.cloud_desc)
        end

        tags = MU::MommaCat.listStandardTags
        tags.merge!(MU::MommaCat.listOptionalTags) if @config['optional_tags']

        if !@config['tags'].nil?
          @config['tags'].each { |tag|
            tags[tag['key']] = tag['value']
          }
        end

        if @config.has_key?("monitor") and !@config['monitor']
          tags['nomonitor'] = true
        end

        chef_node.normal['tags'] = tags
        chef_node.save

        # If we have a database make sure we grant access to that vault.
        # In some cases the cached getLitter response will not have all the resources in the deploy, so lets not use the cache.
        if @config.has_key?('dependencies')
          deploy = MU::MommaCat.getLitter(MU.deploy_id, use_cache: false)
          @config['dependencies'].each{ |dep|
            if dep['type'] == "database" && deploy.deployment.has_key?("databases") && deploy.deployment["databases"].has_key?(dep['name'])
                deploy.deployment["databases"][dep['name']].values.each { |database|
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

      def knifeCmd(cmd, showoutput = false)
        self.class.knifeCmd(cmd, showoutput)
      end

      # Upload the certificate to a Chef Vault for this node
      def stashHostSSLCertSecret
        cert, key = @server.deploy.nodeSSLCerts(@server)
        certdata = {
          "data" => {
            "node.crt" => cert.to_pem.chomp!.gsub(/\n/, "\\n"),
            "node.key" => key.to_pem.chomp!.gsub(/\n/, "\\n")
          }
        }
        saveSecret(item: "ssl_cert", data: certdata, permissions: nil)

        saveSecret(item: "secrets", data: @config['secrets'], permissions: nil) if !@config['secrets'].nil?
        certdata
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
        multiple.map! { |entry|
          if !entry.match(/^role|recipe\[/)
            "#{type}[#{entry}]"
          else
            entry
          end
        }

        if !ignore_missing
          role_list = nil
          recipe_list = nil
          missing = false
          multiple.each { |entry|
            # Rather than argue about whether to expect a bare entry name or
            # require entry[rolename], let's just accomodate.
            if entry.match(/^role\[(.+?)\]/)
              entry_name = Regexp.last_match(1)
              if role_list.nil?
                query=%Q{#{MU::Groomer::Chef.knife} role list};
                role_list = %x{#{query}}
              end
              if !role_list.match(/(^|\n)#{entry_name}($|\n)/)
                MU.log "Attempting to add non-existent #{entry} to #{@server.mu_name}", MU::WARN
                missing = true
              end
            elsif entry.match(/^recipe\[(.+?)\]/)
              entry_name = Regexp.last_match(1)
              if recipe_list.nil?
                query=%Q{#{MU::Groomer::Chef.knife} recipe list};
                recipe_list = %x{#{query}}
              end
              if !recipe_list.match(/(^|\n)#{entry_name}($|\n)/)
                MU.log "Attempting to add non-existent #{entry} to #{@server.mu_name}", MU::WARN
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
            # XXX rescue StandardError is bad style
        rescue StandardError => e
          raise MuError, "FAIL: #{MU::Groomer::Chef.knife} node run_list add #{@server.mu_name} \"#{rl_string}\": #{e.message} (output was #{output})"
        end
      end

    end # class Chef
  end # class Groomer
end # Module Mu
