# Copyright:: Copyright (c) 2019 eGlobalTech, Inc., all rights reserved
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
  # management tools, like Ansible or Puppet.
  class Groomer
    # Support for Ansible as a host configuration management layer.
    class Ansible
      require 'open3'

      # Failure to load or create a deploy
      class NoAnsibleExecError < MuError;
      end

      # One or more Python dependencies missing
      class AnsibleLibrariesError < MuError;
      end

      # Location in which we'll find our Ansible executables. This only applies
      # to full-grown Mu masters; minimalist gem installs will have to make do
      # with whatever Ansible executables they can find in $PATH.
      BINDIR = "/usr/local/python-current/bin"
      @@pwfile_semaphore = Mutex.new


      # @param node [MU::Cloud::Server]: The server object on which we'll be operating
      def initialize(node)
        @config = node.config
        @server = node
        @inventory = Inventory.new(node.deploy)
        @mu_user = node.deploy.mu_user
        @ansible_path = node.deploy.deploy_dir+"/ansible"
        @ansible_execs = MU::Groomer::Ansible.ansibleExecDir

        if !MU::Groomer::Ansible.checkPythonDependencies(@server.windows?)
          raise AnsibleLibrariesError, "One or more python dependencies not available"
        end

        if !@ansible_execs or @ansible_execs.empty?
          raise NoAnsibleExecError, "No Ansible executables found in visible paths"
        end

        [@ansible_path, @ansible_path+"/roles", @ansible_path+"/vars", @ansible_path+"/group_vars", @ansible_path+"/vaults"].each { |dir|
          if !Dir.exist?(dir)
            MU.log "Creating #{dir}", MU::DEBUG
            Dir.mkdir(dir, 0755)
          end
        }
        MU::Groomer::Ansible.vaultPasswordFile(pwfile: "#{@ansible_path}/.vault_pw")
        installRoles
      end

      # Are Ansible executables and key libraries present and accounted for?
      def self.available?(windows = false)
        MU::Groomer::Ansible.checkPythonDependencies(windows)
      end

      # Indicate whether our server has been bootstrapped with Ansible
      def haveBootstrapped?
        @inventory.haveNode?(@server.mu_name)
      end

      # @param vault [String]: A repository of secrets to create/save into.
      # @param item [String]: The item within the repository to create/save.
      # @param data [Hash]: Data to save
      # @param permissions [Boolean]: If true, save the secret under the current active deploy (if any), rather than in the global location for this user
      # @param deploy_dir [String]: If permissions is +true+, save the secret here
      def self.saveSecret(vault: nil, item: nil, data: nil, permissions: false, deploy_dir: nil, quiet: false)

        if vault.nil? or vault.empty? or item.nil? or item.empty?
          raise MuError, "Must call saveSecret with vault and item names"
        end
        if vault.match(/\//) or item.match(/\//) #XXX this should just check for all valid dirname/filename chars
          raise MuError, "Ansible vault/item names cannot include forward slashes"
        end
        pwfile = vaultPasswordFile
        vault_cmd = %Q{#{ansibleExecDir}/ansible-vault}

        dir = if permissions
          if deploy_dir
            deploy_dir+"/ansible/vaults/"+vault
          elsif MU.mommacat
            MU.mommacat.deploy_dir+"/ansible/vaults/"+vault
          else
            raise "MU::Ansible::Groomer.saveSecret had permissions set to true, but I couldn't find an active deploy directory to save into"
          end
        else
          secret_dir+"/"+vault
        end
        path = dir+"/"+item

        if !Dir.exist?(dir)
          FileUtils.mkdir_p(dir, mode: 0700)
        end

        if File.exist?(path) and !quiet
          MU.log "Overwriting existing vault #{vault} item #{item}"
        end

        File.open(path, File::CREAT|File::RDWR|File::TRUNC, 0600) { |f|
          f.write data.to_yaml
        }

        cmd = %Q{#{vault_cmd} encrypt #{path} --vault-password-file #{pwfile}}
        MU.log cmd if !quiet
        raise MuError, "Failed Ansible command: #{cmd}" if !system(cmd)

        # If we're stashing things under a deploy, go ahead and munge them into
        # variables that actual Ansible tasks can get at
        if permissions
          encrypted_string = File.read(path).chomp
          dir = (deploy_dir ? deploy_dir : MU.mommacat.deploy_dir)+"/ansible"
          FileUtils.mkdir_p(dir, mode: 0700) if !Dir.exist?(dir)
          FileUtils.mkdir_p(dir+"/vars", mode: 0700) if !Dir.exist?(dir+"/vars")
          vars_file = "#{dir}/vars/#{vault}.yml"

          vars = if File.exists?(vars_file)
            YAML.load(File.read(vars_file))
          else
            {}
          end
          vars[item] = encrypted_string
          File.open(vars_file, File::CREAT|File::RDWR|File::TRUNC, 0600) { |f|
            f.flock(File::LOCK_EX)
            f.puts vars.to_yaml
            f.flock(File::LOCK_UN)
          }
        end
      end

      # see {MU::Groomer::Ansible.saveSecret}
      def saveSecret(vault: @server.mu_name, item: nil, data: nil, permissions: true, quiet: false)
        self.class.saveSecret(vault: vault, item: item, data: data, permissions: permissions, deploy_dir: @server.deploy.deploy_dir, quiet: quiet)
      end

      # Retrieve sensitive data, which hopefully we're storing and retrieving
      # in a secure fashion.
      # @param vault [String]: A repository of secrets to search
      # @param item [String]: The item within the repository to retrieve
      # @param field [String]: OPTIONAL - A specific field within the item to return.
      # @return [Hash]
      def self.getSecret(vault: nil, item: nil, field: nil, deploy_dir: nil, quiet: false, cmd_only: false)
        if vault.nil? or vault.empty?
          raise MuError, "Must call getSecret with at least a vault name"
        end
        pwfile = vaultPasswordFile

        dir = nil
        try = [secret_dir+"/"+vault]
        try << deploy_dir+"/ansible/vaults/"+vault if deploy_dir
        try << MU.mommacat.deploy_dir+"/ansible/vaults/"+vault if MU.mommacat.deploy_dir
        try.each { |maybe_dir|
          if Dir.exist?(maybe_dir) and (item.nil? or File.exist?(maybe_dir+"/"+item))
            dir = maybe_dir
            break
          end
        }
        if dir.nil?
          raise MuNoSuchSecret, "No such vault #{vault}"
        end

        data = nil
        if item
          itempath = dir+"/"+item
          if !File.exist?(itempath)
            raise MuNoSuchSecret, "No such item #{item} in vault #{vault}"
          end
          cmd = %Q{#{ansibleExecDir}/ansible-vault view #{itempath} --vault-password-file #{pwfile}}
          return cmd if cmd_only
          MU.log cmd if !quiet
          a = `#{cmd}`
          # If we happen to have stored recognizeable JSON or YAML, return it
          # as parsed, which is a behavior we're used to from Chef vault.
          # Otherwise, return a String.
          begin
            data = JSON.parse(a)
          rescue JSON::ParserError
            begin
              data = YAML.load(a)
            rescue Psych::SyntaxError => e
              data = a
            end
          end
          [vault, item, field].each { |tier|
            if data and data.is_a?(Hash) and tier and data[tier]
              data = data[tier]
            end
          }
        else
          data = []
          Dir.foreach(dir) { |entry|
            next if entry == "." or entry == ".."
            next if File.directory?(dir+"/"+entry)
            data << entry
          }
        end

        data
      end

      # see {MU::Groomer::Ansible.getSecret}
      def getSecret(vault: @server.mu_name, item: nil, field: nil, quiet: false, cmd_only: false)
        self.class.getSecret(vault: vault, item: item, field: field, deploy_dir: @server.deploy.deploy_dir, quiet: quiet, cmd_only: cmd_only)
      end

      # Delete a Ansible data bag / Vault
      # @param vault [String]: A repository of secrets to delete
      def self.deleteSecret(vault: nil, item: nil)
        if vault.nil? or vault.empty?
          raise MuError, "Must call deleteSecret with at least a vault name"
        end
        dir = secret_dir+"/"+vault
        if !Dir.exist?(dir)
          raise MuNoSuchSecret, "No such vault #{vault}"
        end

        if item
          itempath = dir+"/"+item
          if !File.exist?(itempath)
            raise MuNoSuchSecret, "No such item #{item} in vault #{vault}"
          end
          MU.log "Deleting Ansible vault #{vault} item #{item}", MU::NOTICE
          File.unlink(itempath)
        else
          MU.log "Deleting Ansible vault #{vault}", MU::NOTICE
          FileUtils.rm_rf(dir)
        end

      end

      # see {MU::Groomer::Ansible.deleteSecret}
      def deleteSecret(vault: nil, item: nil)
        self.class.deleteSecret(vault: vault, item: item)
      end

      # Invoke the Ansible client on the node at the other end of a provided SSH
      # session.
      # @param purpose [String]: A string describing the purpose of this client run.
      # @param max_retries [Integer]: The maximum number of attempts at a successful run to make before giving up.
      # @param output [Boolean]: Display Ansible's regular (non-error) output to the console
      # @param override_runlist [String]: Use the specified run list instead of the node's configured list
      def run(purpose: "Ansible run", update_runlist: true, max_retries: 10, output: true, override_runlist: nil, reboot_first_fail: false, timeout: 1800)
        bootstrap
        pwfile = MU::Groomer::Ansible.vaultPasswordFile
        stashHostSSLCertSecret

        ssh_user = @server.config['ssh_user'] || "root"

        if update_runlist
          bootstrap
        end

        tmpfile = nil
        playbook = if override_runlist and !override_runlist.empty?
          play = {
            "hosts" => @server.config['name']
          }
          if !@server.windows? and @server.config['ssh_user'] != "root"
            play["become"] = "yes"
          end
          play["roles"] = override_runlist if @server.config['run_list'] and !@server.config['run_list'].empty?
          play["vars"] = @server.config['ansible_vars'] if @server.config['ansible_vars']

          tmpfile = Tempfile.new("#{@server.config['name']}-override-runlist.yml")
          tmpfile.puts [play].to_yaml
          tmpfile.close
          tmpfile.path
        else
          "#{@server.config['name']}.yml"
        end

        cmd = %Q{cd #{@ansible_path} && echo "#{purpose}" && #{@ansible_execs}/ansible-playbook -i hosts #{playbook} --limit=#{@server.windows? ? @server.canonicalIP : @server.mu_name} --vault-password-file #{pwfile} --timeout=30 --vault-password-file #{@ansible_path}/.vault_pw -u #{ssh_user}}

        if @server.config['vault_access']
          @server.config['vault_access'].each { |entry|
            vault = entry['vault'] || @server.deploy.deploy_id
            begin
              MU.log "To retrieve secret #{vault}:#{entry['item']} - "+getSecret(vault: vault, item: entry['item'], cmd_only: true), MU::SUMMARY
            rescue MuNoSuchSecret
            end
          }
        end

        retries = 0
        begin
          MU.log cmd
          Timeout::timeout(timeout) {
            if output
              system("#{cmd}")
            else
              %x{#{cmd} 2>&1}
            end

            if $?.exitstatus != 0
              raise MU::Groomer::RunError, "Failed Ansible command: #{cmd}"
            end
          }
        rescue Timeout::Error, MU::Groomer::RunError => e
          if retries < max_retries
            if reboot_first_fail and e.class.name == "MU::Groomer::RunError"
              @server.reboot
              reboot_first_fail = false
            end
            sleep 30
            retries += 1
            MU.log "Failed Ansible run, will retry (#{retries.to_s}/#{max_retries.to_s})", MU::NOTICE, details: cmd

            retry
          else
            tmpfile.unlink if tmpfile
            raise MuError, "Failed Ansible command: #{cmd}"
          end
        end

        tmpfile.unlink if tmpfile
      end

      # This is a stub; since Ansible is effectively agentless, this operation
      # doesn't have meaning.
      def preClean(leave_ours = false)
      end

      # This is a stub; since Ansible is effectively agentless, this operation
      # doesn't have meaning.
      def reinstall
      end

      # Bootstrap our server with Ansible- basically, just make sure this node
      # is listed in our deployment's Ansible inventory.
      def bootstrap
        @inventory.add(@server.config['name'], @server.windows? ? @server.canonicalIP : @server.mu_name)
        play = {
          "hosts" => @server.config['name']
        }

        if !@server.windows? and @server.config['ssh_user'] != "root"
          play["become"] = "yes"
        end

        play["roles"] = ["mu-base"]
        if @server.config['run_list']
          play["roles"].concat(@server.config['run_list'])
        end

        if @server.config['ansible_vars']
          play["vars"] = @server.config['ansible_vars']
        end

        if @server.windows?
          play["vars"] ||= {}
          play["vars"]["ansible_connection"] = "winrm"
          play["vars"]["ansible_winrm_scheme"] = "https"
          play["vars"]["ansible_winrm_transport"] = "ntlm"
          play["vars"]["ansible_winrm_server_cert_validation"] = "ignore" # XXX this sucks; use Mu_CA.pem if we can get it to work
#          play["vars"]["ansible_winrm_ca_trust_path"] = "#{MU.mySSLDir}/Mu_CA.pem"
          play["vars"]["ansible_user"] = @server.config['windows_admin_username']
          win_pw = @server.getWindowsAdminPassword

          pwfile = MU::Groomer::Ansible.vaultPasswordFile
          cmd = %Q{#{MU::Groomer::Ansible.ansibleExecDir}/ansible-vault}
          output = %x{#{cmd} encrypt_string '#{win_pw.gsub(/'/, "\\\\'")}' --vault-password-file #{pwfile}}

          play["vars"]["ansible_password"] = output
        end

        File.open(@ansible_path+"/"+@server.config['name']+".yml", File::CREAT|File::RDWR|File::TRUNC, 0600) { |f|
          f.flock(File::LOCK_EX)
          f.puts [play].to_yaml.sub(/ansible_password: \|-?[\n\s]+/, 'ansible_password: ') # Ansible doesn't like this (legal) YAML
          f.flock(File::LOCK_UN)
        }
      end

      # Synchronize the deployment structure managed by {MU::MommaCat} into some Ansible variables, so that nodes can access this metadata.
      # @return [Hash]: The data synchronized.
      def saveDeployData
        @server.describe

        allvars = {
          "mu_deployment" => MU::Config.stripConfig(@server.deploy.deployment),
          "mu_service_name" => @config["name"],
          "mu_name" => @server.mu_name,
          "mu_deploy_id" => @server.deploy.deploy_id,
          "mu_canonical_ip" => @server.canonicalIP,
          "mu_admin_email" => $MU_CFG['mu_admin_email'],
          "mu_environment" => MU.environment.downcase,
          "mu_vaults" => {}
        }
        allvars['mu_deployment']['ssh_public_key'] = @server.deploy.ssh_public_key

        vaultdir = @ansible_path+"/vaults"
        if Dir.exists?(vaultdir)
          Dir.entries(vaultdir).each { |v|
            next if !File.directory?(vaultdir+"/"+v)
            next if [".", ".."].include?(v)
            Dir.entries(vaultdir+"/"+v).each { |i|
              next if File.directory?(vaultdir+"/"+v+"/"+i)
              value = getSecret(vault: v, item: i, quiet: true)
              next if !value # ignore corrupted data

              # Ansible struggles to actually use this. The only thing that
              # seems to work is writing it (decrypted) to a tmp file on the
              # target host then reading that back, which is both ugly and
              # insecure. None of these workarounds seem to do the thing:
              # https://github.com/ansible/ansible/issues/24425
              allvars["mu_vaults"][v] ||= {}
              allvars["mu_vaults"][v].merge!(YAML.load(self.class.encryptString(value.to_yaml, i)))
            }
          }
        end

        if @server.config['cloud'] == "AWS"
          allvars["ec2"] = MU.structToHash(@server.cloud_desc, stringify_keys: true)
        end

        if @server.windows?
          allvars['windows_admin_username'] = @config['windows_admin_username']
        end

        if !@server.cloud.nil?
          allvars["cloudprovider"] = @server.cloud
        end

        File.open(@ansible_path+"/vars/main.yml", File::CREAT|File::RDWR|File::TRUNC, 0600) { |f|
          f.flock(File::LOCK_EX)
          f.puts allvars.to_yaml
          f.flock(File::LOCK_UN)
        }

        groupvars = allvars.dup
        if @server.deploy.original_config.has_key?('parameters')
          groupvars["mu_parameters"] = @server.deploy.original_config['parameters']
        end
        if !@config['application_attributes'].nil?
          groupvars["application_attributes"] = @config['application_attributes']
        end
        if !@config['groomer_variables'].nil?
          groupvars["mu"] = @config['groomer_variables']
        end

        File.open(@ansible_path+"/group_vars/"+@server.config['name']+".yml", File::CREAT|File::RDWR|File::TRUNC, 0600) { |f|
          f.flock(File::LOCK_EX)
          f.puts groupvars.to_yaml
          f.flock(File::LOCK_UN)
        }

        allvars['deployment']
      end

      # Nuke everything associated with a deploy. Since we're just some files
      # in the deploy directory, this doesn't have to do anything.
      def self.cleanup(deploy_id, noop = false)
#        deploy = MU::MommaCat.new(MU.deploy_id)
#        inventory = Inventory.new(deploy)
      end

      # Expunge Ansible resources associated with a node.
      # @param node [String]: The Mu name of the node in question.
      # @param _vaults_to_clean [Array<Hash>]: Dummy argument, part of this method's interface but not used by the Ansible layer
      # @param noop [Boolean]: Skip actual deletion, just state what we'd do
      def self.purge(node, _vaults_to_clean = [], noop = false)
        deploy = MU::MommaCat.new(MU.deploy_id)
        inventory = Inventory.new(deploy)
#        ansible_path = deploy.deploy_dir+"/ansible"
        if !noop
          inventory.remove(node)
        end
      end

      # List the Ansible vaults, if any, owned by the specified Mu user
      # @param user [String]: The user whose vaults we will list
      # @return [Array<String>]
      def self.listSecrets(user = MU.mu_user)
        path = secret_dir(user)
        found = []
        Dir.foreach(path) { |entry|
          next if entry == "." or entry == ".."
          next if !File.directory?(path+"/"+entry)
          found << entry
        }
        found
      end

      # Encrypt a string using +ansible-vault encrypt_string+ and return +STDOUT+
      # @param string [String]: The string to encrypt
      # @param name [String]: A name to use for the string's YAML key
      def self.encryptString(string, name = nil)
        pwfile = vaultPasswordFile
        cmd = %Q{#{ansibleExecDir}/ansible-vault}

        stdout, status = if name
           Open3.capture2(cmd, "encrypt_string", string, "--name", name, "--vault-password-file", pwfile)
        else
          Open3.capture2(cmd, "encrypt_string", string, "--vault-password-file", pwfile)
        end

        if !status.success?
          raise MuError, "Failed Ansible command: #{cmd} encrypt_string <redacted> --name #{name} --vault-password-file"
        end
        stdout.strip
      end

      # Hunt down and return a path for a Python executable
      # @return [String]
      def self.pythonExecDir
        path = nil

        if File.exist?(BINDIR+"/python")
          path = BINDIR
        else
          paths = [ansibleExecDir]
          paths.concat(ENV['PATH'].split(/:/))
          paths << "/usr/bin" # not always in path, esp in pared-down Docker images
          paths.reject! { |p| p.nil? }
          paths.uniq.each { |bindir|
            if File.exist?(bindir+"/python")
              path = bindir
              break
            end
          }
        end
        path
      end

      # Make sure what's in our Python requirements.txt is reflected in the
      # Python we're about to run for Ansible
      def self.checkPythonDependencies(windows = false)
        return nil if !ansibleExecDir

        execline = File.readlines(ansibleExecDir+"/ansible-playbook").first.chomp.sub(/^#!/, '')
        if !execline
          MU.log "Unable to extract a Python executable from #{ansibleExecDir}/ansible-playbook", MU::ERR
          return false
        end

        require 'tempfile'
        f = Tempfile.new("pythoncheck")
        f.puts "import ansible"
        f.puts "import winrm" if windows
        f.close

        system(%Q{#{execline} #{f.path}})
        f.unlink
        $?.exitstatus == 0 ? true : false
      end

      # Hunt down and return a path for Ansible executables
      # @return [String]
      def self.ansibleExecDir
        path = nil
        if File.exist?(BINDIR+"/ansible-playbook")
          path = BINDIR
        else
          paths = ENV['PATH'].split(/:/)
          paths << "/usr/bin"
          paths.uniq.each { |bindir|
            if File.exist?(bindir+"/ansible-playbook")
              path = bindir
              if !File.exist?(bindir+"/ansible-vault")
                MU.log "Found ansible-playbook executable in #{bindir}, but no ansible-vault. Vault functionality will not work!", MU::WARN
              end
              if !File.exist?(bindir+"/ansible-galaxy")
                MU.log "Found ansible-playbook executable in #{bindir}, but no ansible-galaxy. Automatic community role fetch will not work!", MU::WARN
              end
              break
            end
          }
        end
        path
      end

      # Get path to the +.vault_pw+ file for the appropriate user. If it
      # doesn't exist, generate it. 
      #
      # @param for_user [String]:
      # @param pwfile [String]
      # @return [String]
      def self.vaultPasswordFile(for_user = nil, pwfile: nil)
        pwfile ||= secret_dir(for_user)+"/.vault_pw"
        @@pwfile_semaphore.synchronize {
          if !File.exist?(pwfile)
            MU.log "Generating Ansible vault password file at #{pwfile}", MU::DEBUG
            File.open(pwfile, File::CREAT|File::RDWR|File::TRUNC, 0400) { |f|
              f.write Password.random(12..14)
            }
          end
        }
        pwfile
      end

      # Figure out where our main stash of secrets is, and make sure it exists
      # @param user [String]:
      # @return [String]
      def self.secret_dir(user = MU.mu_user)
        path = MU.dataDir(user) + "/ansible-secrets"
        Dir.mkdir(path, 0755) if !Dir.exist?(path)

        path
      end

      private

      # Figure out where our main stash of secrets is, and make sure it exists
      def secret_dir
        MU::Groomer::Ansible.secret_dir(@mu_user)
      end

      # Make an effort to distinguish an Ansible role from other sorts of
      # artifacts, since 'roles' is an awfully generic name for a directory.
      # Short of a full, slow syntax check, this is the best we're liable to do.
      def isAnsibleRole?(path)
        begin
        Dir.foreach(path) { |entry|
          if File.directory?(path+"/"+entry) and
             ["tasks", "vars"].include?(entry)
            return true # https://knowyourmeme.com/memes/close-enough
          elsif ["metadata.rb", "recipes"].include?(entry)
            return false
          end
        }
        rescue Errno::ENOTDIR
        end
        false
      end

      # Find all of the Ansible roles in the various configured Mu repositories
      # and 
      def installRoles
        roledir = @ansible_path+"/roles"

        canon_links = {}

        repodirs = []

        # Make sure we search the global ansible_dir, if any is set
        if $MU_CFG and $MU_CFG['ansible_dir'] and !$MU_CFG['ansible_dir'].empty?
          if !Dir.exist?($MU_CFG['ansible_dir'])
            MU.log "Config lists an Ansible directory at #{$MU_CFG['ansible_dir']}, but I see no such directory", MU::WARN
          else
            repodirs << $MU_CFG['ansible_dir']
          end
        end

        # Hook up any Ansible roles listed in our platform repos
        if $MU_CFG and $MU_CFG['repos']
          $MU_CFG['repos'].each { |repo|
            repo.match(/\/([^\/]+?)(\.git)?$/)
            shortname = Regexp.last_match(1)
            repodirs << MU.dataDir + "/" + shortname
          }
        end

        repodirs.each { |repodir|
          ["roles", "ansible/roles"].each { |subdir|
            next if !Dir.exist?(repodir+"/"+subdir)
            Dir.foreach(repodir+"/"+subdir) { |role|
              next if [".", ".."].include?(role)
              realpath = repodir+"/"+subdir+"/"+role
              link = roledir+"/"+role
              
              if isAnsibleRole?(realpath)
                if !File.exist?(link)
                  File.symlink(realpath, link)
                  canon_links[role] = realpath
                elsif File.symlink?(link)
                  cur_target = File.readlink(link)
                  if cur_target == realpath
                    canon_links[role] = realpath
                  elsif !canon_links[role]
                    File.unlink(link)
                    File.symlink(realpath, link)
                    canon_links[role] = realpath
                  end
                end
              end
            }
          }
        }

        # Now layer on everything bundled in the main Mu repo
        Dir.foreach(MU.myRoot+"/ansible/roles") { |role|
          next if [".", ".."].include?(role)
          next if File.exist?(roledir+"/"+role)
          File.symlink(MU.myRoot+"/ansible/roles/"+role, roledir+"/"+role)
        }

        if @server.config['run_list']
          @server.config['run_list'].each { |role|
            found = false
            if !File.exist?(roledir+"/"+role)
              if role.match(/[^\.]\.[^\.]/) and @server.config['groomer_autofetch']
                system(%Q{#{@ansible_execs}/ansible-galaxy}, "--roles-path", roledir, "install", role)
                found = true
# XXX check return value
              else
                canon_links.keys.each { |longrole|
                  if longrole.match(/\.#{Regexp.quote(role)}$/)
                    File.symlink(roledir+"/"+longrole, roledir+"/"+role)
                    found = true
                    break
                  end
                }
              end
            else
              found = true
            end
            if !found
              raise MuError, "Unable to locate Ansible role #{role}"
            end
          }
        end
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
        saveSecret(item: "ssl_cert", data: certdata, permissions: true)

        saveSecret(item: "secrets", data: @config['secrets'], permissions: true) if !@config['secrets'].nil?
        certdata
      end

      # Simple interface for an Ansible inventory file.
      class Inventory

        # @param deploy [MU::MommaCat]
        def initialize(deploy)
          @deploy = deploy
          @ansible_path = @deploy.deploy_dir+"/ansible"
          if !Dir.exist?(@ansible_path)
            Dir.mkdir(@ansible_path, 0755)
          end

          @lockfile = File.open(@ansible_path+"/.hosts.lock", File::CREAT|File::RDWR, 0600)
        end

        # See if we have a particular node in our inventory.
        def haveNode?(name)
          lock
          read
          @inv.values.each { |nodes|
            if nodes.include?(name)
              unlock
              return true
            end
          }
          unlock
          false
        end

        # Add a node to our Ansible inventory
        # @param group [String]: The host group to which the node belongs
        # @param name [String]: The hostname or IP of the node
        def add(group, name)
          if group.nil? or group.empty? or name.nil? or name.empty?
            raise MuError, "Ansible::Inventory.add requires both a host group string and a name"
          end
          lock
          read
          @inv[group] ||= []
          @inv[group] << name
          @inv[group].uniq!
          save!
          unlock
        end

        # Remove a node from our Ansible inventory
        # @param name [String]: The hostname or IP of the node
        def remove(name)
          lock
          read
          @inv.each_pair { |_group, nodes|
            nodes.delete(name)
          }
          save!
          unlock
        end

        private

        def lock
          @lockfile.flock(File::LOCK_EX)
        end

        def unlock
          @lockfile.flock(File::LOCK_UN)
        end

        def save!
          @inv ||= {}

          File.open(@ansible_path+"/hosts", File::CREAT|File::RDWR|File::TRUNC, 0600) { |f|
            @inv.each_pair { |group, hosts|
              next if hosts.size == 0 # don't write empty groups
              f.puts "["+group+"]"
              f.puts hosts.join("\n")
            }
          }
        end

        def read
          @inv = {}
          if File.exist?(@ansible_path+"/hosts")
            section = nil
            File.readlines(@ansible_path+"/hosts").each { |l|
              l.chomp!
              l.sub!(/#.*/, "")
              next if l.empty?
              if l.match(/\[(.+?)\]/)
                section = Regexp.last_match[1]
                @inv[section] ||= []
              else
                @inv[section] << l
              end
            }
          end

          @inv
        end

      end

    end # class Ansible
  end # class Groomer
end # Module Mu
