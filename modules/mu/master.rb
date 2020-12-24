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

  # Routines for use management and configuration on the Mu Master.
  class Master
    require 'date'
    require 'colorize'
    require 'fileutils'
    autoload :Chef, 'mu/master/chef'
    autoload :LDAP, 'mu/master/ldap'
    autoload :SSL, 'mu/master/ssl'

    # Home directory of the invoking user
    MY_HOME = Etc.getpwuid(Process.uid).dir

    # Home directory of the Nagios user, if we're in a non-gem context
    NAGIOS_HOME = "/opt/mu/var/nagios_user_home" # XXX gross

    # @param users [Hash]: User metadata of the type returned by listUsers
    def self.printUsersToTerminal(users = MU::Master.listUsers)
      labeled = false
      users.keys.sort.each { |username|
        data = users[username]
        if data['admin']
          if !labeled
            labeled = true
            puts "Administrators".light_cyan.on_black.bold
          end
          append = ""
          append = " (Chef and local system ONLY)".bold if data['non_ldap']
          append = append + "(" + data['uid'] + ")" if data.has_key?('uid')
          puts "#{username.bold} - #{data['realname']} <#{data['email']}>"+append
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
      change_uid: -1,
      orgs: [],
      remove_orgs: []
    )
      create = false
      cur_users = listUsers
      create = true if !cur_users.has_key?(username)
      if !MU::Master::LDAP.manageUser(username, name: name, email: email, password: password, admin: admin, change_uid: change_uid)
        deleteUser(username) if create
        return false
      end
      %x{sh -x /etc/init.d/oddjobd start 2>&1 > /dev/null} # oddjobd dies, like a lot
      begin
        Etc.getpwnam(username)
      rescue ArgumentError
        return false
      end
      chef_username ||= username.dup
      %x{/bin/su - #{username} -c "ls > /dev/null"}
      if !MU::Master::Chef.manageUser(chef_username, ldap_user: username, name: name, email: email, admin: admin, orgs: orgs, remove_orgs: remove_orgs) and create
        deleteUser(username) if create
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
          f.puts Erubis::Eruby.new(File.read("#{$MU_CFG['libdir']}/install/user-dot-murc.erb")).result(vars)
        }
        File.open(home+"/.bashrc", "a"){ |f|
          f.puts "source #{home}/.murc"
        }
        FileUtils.chown_R(username, username+".mu-user", Etc.getpwnam(username).dir)
        %x{/sbin/restorecon -r /home}
      end
      true
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
        rescue MU::Groomer::MuNoSuchSecret
          MU::Groomer::Chef.saveSecret(vault: "scratchpad", item: itemname, data: data)
          return itemname
        end while true
      }
    end

    # Create and mount a disk local to the Mu master, optionally using luks to
    # encrypt it. This makes a few assumptions: that mu-master::init has been
    # run, and that utilities like mkfs.xfs exist.
    # TODO add parameters to use filesystems other than XFS, alternate paths, etc
    # @param device [String]: The disk device, by the name we want to see from the OS side
    # @param path [String]: The path where we'll mount the device
    # @param size [Integer]: The size of the disk, in GB
    # @param cryptfile [String]: The name of a luks encryption key, which we'll look for in MU.adminBucketName
    # @param ramdisk [String]: The name of a ramdisk to use when mounting encrypted disks
    def self.disk(device, path, size = 50, cryptfile = nil, ramdisk = "ram7")
      temp_dev = "/dev/#{ramdisk}"

      if !File.open("/etc/mtab").read.match(/ #{path} /)
        realdevice = if MU::Cloud::Google.hosted?
          "/dev/disk/by-id/google-"+device.gsub(/.*?\/([^\/]+)$/, '\1')
        elsif MU::Cloud::AWS.hosted?
          MU::Cloud::AWS.realDevicePath(device.dup)
        else
          device.dup
        end
        alias_device = cryptfile ? "/dev/mapper/"+path.gsub(/[^0-9a-z_\-]/i, "_") : realdevice

        if !File.exist?(realdevice)
          MU.log "Creating #{path} volume"
          if MU::Cloud::AWS.hosted?
            dummy_svr = MU::Cloud::AWS::Server.new(
              mu_name: "MU-MASTER",
              cloud_id: MU.myInstanceId,
              kitten_cfg: {}
            )
            dummy_svr.addVolume(device, size)
            MU::Cloud::AWS::Server.tagVolumes(
              MU.myInstanceId,
              device: device,
              tag_name: "Name",
              tag_value: "#{$MU_CFG['hostname']} #{path}"
            )
            # the device might be on some arbitrary NVMe slot
            realdevice = MU::Cloud::AWS.realDevicePath(realdevice)
          elsif MU::Cloud::Google.hosted?
            dummy_svr = MU::Cloud::Google::Server.new(
              mu_name: "MU-MASTER",
              cloud_id: MU.myInstanceId,
              kitten_cfg: { 'project' => MU::Cloud::Google.myProject, 'availability_zone' => MU.myAZ }
            )
            dummy_svr.addVolume(device, size) # This will tag itself sensibly
          else
            raise MuError, "Not in a familiar cloud, so I don't know how to create volumes for myself"
          end
        end

        if cryptfile
          body = nil
          if MU::Cloud::AWS.hosted?
            begin
              resp = MU::Cloud::AWS.s3.get_object(bucket: MU.adminBucketName, key: cryptfile)
              body = resp.body
            rescue StandardError => e
              MU.log "Failed to fetch #{cryptfile} from S3 bucket #{MU.adminBucketName}", MU::ERR, details: e.inspect
              %x{/bin/dd if=/dev/urandom of=#{temp_dev} bs=1M count=1 > /dev/null 2>&1}
              raise e
            end
          elsif MU::Cloud::Google.hosted?
            begin
              body = MU::Cloud::Google.storage.get_object(MU.adminBucketName, cryptfile)
            rescue StandardError => e
              MU.log "Failed to fetch #{cryptfile} from Cloud Storage bucket #{MU.adminBucketName}", MU::ERR, details: e.inspect
              %x{/bin/dd if=/dev/urandom of=#{temp_dev} bs=1M count=1 > /dev/null 2>&1}
              raise e
            end
          else
            raise MuError, "Not in a familiar cloud, so I don't know where to get my luks crypt key (#{cryptfile})"
          end

          keyfile = Tempfile.new(cryptfile)
          keyfile.puts body
          keyfile.close

          # we can assume that mu-master::init installed cryptsetup-luks
          if !File.exist?(alias_device)
            MU.log "Initializing crypto on #{alias_device}", MU::NOTICE
            %x{/sbin/cryptsetup luksFormat #{realdevice} #{keyfile.path} --batch-mode}
            %x{/sbin/cryptsetup luksOpen #{realdevice} #{alias_device.gsub(/.*?\/([^\/]+)$/, '\1')} --key-file #{keyfile.path}}
          end
          keyfile.unlink
        end

        %x{/usr/sbin/xfs_admin -l "#{alias_device}" > /dev/null 2>&1}
        if $?.exitstatus != 0
          MU.log "Formatting #{alias_device}", MU::NOTICE
          %x{/sbin/mkfs.xfs "#{alias_device}"}
          %x{/usr/sbin/xfs_admin -L "#{path.gsub(/[^0-9a-z_\-]/i, "_")}" "#{alias_device}"}
        end
        Dir.mkdir(path, 0700) if !Dir.exist?(path) # XXX recursive
        %x{/usr/sbin/xfs_info "#{alias_device}" > /dev/null 2>&1}
        if $?.exitstatus != 0
          MU.log "Mounting #{alias_device} to #{path}"
          %x{/bin/mount "#{alias_device}" "#{path}"}
        end

        if cryptfile
          %x{/bin/dd if=/dev/urandom of=#{temp_dev} bs=1M count=1 > /dev/null 2>&1}
        end

      end

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

    # Remove Scratchpad entries which have exceeded their maximum age.
    def self.cleanExpiredScratchpads
      return if !$MU_CFG['scratchpad'] or !$MU_CFG['scratchpad'].has_key?('max_age') or $MU_CFG['scratchpad']['max_age'] < 1
      @scratchpad_semaphore.synchronize {
        entries = MU::Groomer::Chef.getSecret(vault: "scratchpad")
        entries.each { |pad|
          data = MU::Groomer::Chef.getSecret(vault: "scratchpad", item: pad)
          if data["timestamp"].to_i < (Time.now.to_i - $MU_CFG['scratchpad']['max_age'])
            MU.log "Deleting expired Scratchpad entry #{pad}", MU::NOTICE
            MU::Groomer::Chef.deleteSecret(vault: "scratchpad", item: pad)
          end
        }
      }
    end

    # @return [Array<Hash>]: List of all Mu users, with pertinent metadata.
    def self.listUsers

      # Handle running in standalone/library mode, sans LDAP, gracefully
      if !$MU_CFG['multiuser']
        stub_user_data = {
          "mu" => {
            "email" => $MU_CFG['mu_admin_email'],
            "monitoring_email" => $MU_CFG['mu_admin_email'],
            "realname" => $MU_CFG['banner'],
            "admin" => true,
            "non_ldap" => true,
          }
        }
        if Etc.getpwuid(Process.uid).name != "root"
          stub_user_data[Etc.getpwuid(Process.uid).name] = stub_user_data["mu"].dup
        end

        return stub_user_data
      end

      if Etc.getpwuid(Process.uid).name != "root" or !Dir.exist?(MU.dataDir+"/users")
        username = Etc.getpwuid(Process.uid).name
        MU.log "Running without LDAP permissions to list users (#{username}), relying on Mu local cache", MU::DEBUG
        userdir = MU.mainDataDir+"/users/#{username}"
        all_user_data = {}
        all_user_data[username] = {}
        ["non_ldap", "email", "monitoring_email", "realname", "chef_user", "admin"].each { |field|
          if File.exist?(userdir+"/"+field)
            all_user_data[username][field] = File.read(userdir+"/"+field).chomp
          elsif ["email", "realname"].include?(field)
            MU.log "Required user field '#{field}' for '#{username}' not set in LDAP or in Mu's disk cache.", MU::WARN
          end
        }
        return all_user_data
      end
      # LDAP is canonical. Everything else is required to be in sync with it.
      ldap_users = MU::Master::LDAP.listUsers
      all_user_data = {}
      ldap_users['mu'] = {}
      ldap_users['mu']['admin'] = true
      ldap_users['mu']['non_ldap'] = true
      ldap_users.each_pair { |uname, data|
        key = uname.to_s
        all_user_data[key] = {}
        userdir = $MU_CFG['installdir']+"/var/users/#{key}"
        if !Dir.exist?(userdir)
          MU.log "No metadata exists for user #{key}, creating stub directory #{userdir}", MU::WARN
          Dir.mkdir(userdir, 0755)
        end

        ["non_ldap", "email", "monitoring_email", "realname", "chef_user", "admin"].each { |field|
          if data.has_key?(field)
            all_user_data[key][field] = data[field]
          elsif File.exist?(userdir+"/"+field)
            all_user_data[key][field] = File.read(userdir+"/"+field).chomp
          elsif ["email", "realname"].include?(field)
            MU.log "Required user field '#{field}' for '#{key}' not set in LDAP or in Mu's disk cache.", MU::WARN
          end
        }
      }
      all_user_data
    end


    @@kubectl_path = nil
    # Locate a working +kubectl+ executable and return its fully-qualified
    # path.
    def self.kubectl
      return @@kubectl_path if @@kubectl_path

      paths = ["/opt/mu/bin"]+ENV['PATH'].split(/:/)
      best = nil
      best_version = nil
      paths.uniq.each { |path|
        path.sub!(/^~/, MY_HOME)
        if File.exist?(path+"/kubectl")
          version = %x{#{path}/kubectl version --short --client}.chomp.sub(/.*Client version:\s+v/i, '')
          next if !$?.success?
          if !best_version or MU.version_sort(best_version, version) > 0
            best_version = version
            best = path+"/kubectl"
          end
        end
      }
      if !best
        MU.log "Failed to find a working kubectl executable in any path", MU::WARN, details: paths.uniq.sort
        return nil
      else
        MU.log "Kubernetes commands will use #{best} (#{best_version})"
      end

      @@kubectl_path = best
      @@kubectl_path
    end

    # Given an array of hashes representing Kubernetes resources, 
    def self.applyKubernetesResources(name, blobs = [], kubeconfig: nil, outputdir: nil)
      use_tmp = false
      if !outputdir
        require 'tempfile'
        use_tmp = true
      end

      count = 0
      blobs.each { |blob|
        f = nil
        blobfile = if use_tmp
          f = Tempfile.new("k8s-resource-#{count.to_s}-#{name}")
          f.puts blob.to_yaml
          f.close
          f.path
        else
          path = outputdir+"/k8s-resource-#{count.to_s}-#{name}"
          File.open(path, "w") { |fh|
            fh.puts blob.to_yaml
          }
          path
        end
        next if !kubectl
        done = false
        retries = 0
        begin
          %x{#{kubectl} --kubeconfig "#{kubeconfig}" get -f #{blobfile} > /dev/null 2>&1}
          arg = $?.exitstatus == 0 ? "apply" : "create"
          cmd = %Q{#{kubectl} --kubeconfig "#{kubeconfig}" #{arg} -f #{blobfile}}
          MU.log "Applying Kubernetes resource #{count.to_s} with kubectl #{arg}", MU::NOTICE, details: cmd
          output = %x{#{cmd} 2>&1}
          if $?.exitstatus == 0
            MU.log "Kubernetes resource #{count.to_s} #{arg} was successful: #{output}", details: blob.to_yaml
            done = true
          else
            MU.log "Kubernetes resource #{count.to_s} #{arg} failed: #{output}", MU::WARN, details: blob.to_yaml
            if retries < 5
              sleep 5
            else
              MU.log "Giving up on Kubernetes resource #{count.to_s} #{arg}"
              done = true
            end
            retries += 1
          end
          f.unlink if use_tmp
        end while !done
        count += 1
      }
    end

    # Update Mu's local cache/metadata for the given user, fixing permissions
    # and updating stored values. Create a single-user group for the user, as
    # well.
    # @param user [String]: The user to update
    # @return [Integer]: The gid of the user's default group
    def self.setLocalDataPerms(user)
      userdir = $MU_CFG['datadir']+"/users/#{user}"
      retries = 0
      user = "root" if user == "mu"
      begin
        group = user == "root" ? Etc.getgrgid(0) : "#{user}.mu-user"
        if user != "root"
          MU.log "/usr/sbin/usermod -a -G '#{group}' '#{user}'", MU::DEBUG
          %x{/usr/sbin/usermod -a -G "#{group}" "#{user}"}
        end
        Dir.mkdir(userdir, 2750) if !Dir.exist?(userdir)
				# XXX mkdir gets the perms wrong for some reason
        MU.log "/bin/chmod 2750 #{userdir}", MU::DEBUG
        %x{/bin/chmod 2750 #{userdir}}
        gid = user == "root" ? 0 : Etc.getgrnam(group).gid
        Dir.foreach(userdir) { |file|
          next if file == ".."
          File.chown(nil, gid, userdir+"/"+file)
          if File.file?(userdir+"/"+file)
            File.chmod(0640, userdir+"/"+file)
          end
        }
        return gid
      rescue ArgumentError => e
        if $MU_CFG["ldap"]["type"] == "Active Directory"
          puts %x{/usr/sbin/groupadd "#{user}.mu-user"}
        else
          MU.log "Got '#{e.message}' trying to set permissions on local files, will retry", MU::WARN
        end
        sleep 5
        if retries <= 5
          retries = retries + 1
          retry
        end
      end
    end

    # Clean a node's entries out of /etc/hosts
    # @param node [String]: The node's name
    # @return [void]
    def self.removeInstanceFromEtcHosts(node)
      return if MU.mu_user != "mu"
      hostsfile = "/etc/hosts"
      FileUtils.copy(hostsfile, "#{hostsfile}.bak-#{MU.deploy_id}")
      File.open(hostsfile, File::CREAT|File::RDWR, 0644) { |f|
        f.flock(File::LOCK_EX)
        newlines = Array.new
        f.readlines.each { |line|
          newlines << line if !line.match(/ #{node}(\s|$)/)
        }
        f.rewind
        f.truncate(0)
        f.puts(newlines)
        f.flush

        f.flock(File::LOCK_UN)
      }
    end


    # Insert node names associated with a new instance into /etc/hosts so we
    # can treat them as if they were real DNS entries. Especially helpful when
    # Chef/Ohai mistake the proper hostname, e.g. when bootstrapping Windows.
    # @param public_ip [String]: The node's IP address
    # @param chef_name [String]: The node's Chef node name
    # @param system_name [String]: The node's local system name
    # @return [void]
    def self.addInstanceToEtcHosts(public_ip, chef_name = nil, system_name = nil)

      # XXX cover ipv6 case
      if public_ip.nil? or !public_ip.match(/^\d+\.\d+\.\d+\.\d+$/) or (chef_name.nil? and system_name.nil?)
        raise MuError, "addInstanceToEtcHosts requires public_ip and one or both of chef_name and system_name!"
      end
      if chef_name == "localhost" or system_name == "localhost"
        raise MuError, "Can't set localhost as a name in addInstanceToEtcHosts"
      end

      if !["mu", "root"].include?(MU.mu_user)
        response = nil
        begin
          response = open("https://127.0.0.1:#{MU.mommaCatPort.to_s}/rest/hosts_add/#{chef_name}/#{public_ip}").read
        rescue Errno::ECONNRESET, Errno::ECONNREFUSED
        end
        if response != "ok"
          MU.log "Unable to add #{public_ip} to /etc/hosts via MommaCat request", MU::WARN
        end
        return
      end

      File.readlines("/etc/hosts").each { |line|
        if line.match(/^#{public_ip} /) or (chef_name != nil and line.match(/ #{chef_name}(\s|$)/)) or (system_name != nil and line.match(/ #{system_name}(\s|$)/))
          MU.log "Ignoring attempt to add duplicate /etc/hosts entry: #{public_ip} #{chef_name} #{system_name}", MU::DEBUG
          return
        end
      }
      File.open("/etc/hosts", 'a') { |etc_hosts|
        etc_hosts.flock(File::LOCK_EX)
        etc_hosts.puts("#{public_ip} #{chef_name} #{system_name}")
        etc_hosts.flock(File::LOCK_UN)
      }
      MU.log("Added to /etc/hosts: #{public_ip} #{chef_name} #{system_name}")
    end

    @ssh_semaphore = Mutex.new
    # Insert a definition for a node into our SSH config.
    # @param server [MU::Cloud::Server]: The name of the node.
    # @param names [Array<String>]: Other names that we'd like this host to be known by for SSH purposes
    # @param ssh_dir [String]: The configuration directory of the SSH config to emit.
    # @param ssh_conf [String]: A specific SSH configuration file to write entries into.
    # @param ssh_owner [String]: The preferred owner of the SSH configuration files.
    # @param timeout [Integer]: An alternate timeout value for connections to this server.
    # @return [void]
    def self.addHostToSSHConfig(server,
        ssh_dir: "#{Etc.getpwuid(Process.uid).dir}/.ssh",
        ssh_conf: "#{Etc.getpwuid(Process.uid).dir}/.ssh/config",
        ssh_owner: Etc.getpwuid(Process.uid).name,
        names: [],
        timeout: 0
    )
      if server.nil?
        MU.log "Called addHostToSSHConfig without a MU::Cloud::Server object", MU::ERR, details: caller
        return nil
      end

      _nat_ssh_key, nat_ssh_user, nat_ssh_host, canonical_ip, ssh_user, ssh_key_name = begin
        server.getSSHConfig
      rescue MU::MuError
        return
      end

      if ssh_user.nil? or ssh_user.empty?
        MU.log "Failed to extract ssh_user for #{server.mu_name} addHostToSSHConfig", MU::ERR
        return
      end
      if canonical_ip.nil? or canonical_ip.empty?
        MU.log "Failed to extract canonical_ip for #{server.mu_name} addHostToSSHConfig", MU::ERR
        return
      end
      if ssh_key_name.nil? or ssh_key_name.empty?
        MU.log "Failed to extract ssh_key_name for #{server.mu_name} in addHostToSSHConfig", MU::ERR
        return
      end

      @ssh_semaphore.synchronize {

        if File.exist?(ssh_conf)
          File.readlines(ssh_conf).each { |line|
            if line.match(/^Host #{server.mu_name} /)
              MU.log("Attempt to add duplicate #{ssh_conf} entry for #{server.mu_name}", MU::WARN)
              return
            end
          }
        end

        File.open(ssh_conf, 'a', 0600) { |ssh_config|
          ssh_config.flock(File::LOCK_EX)
          host_str = "Host #{server.mu_name} #{server.canonicalIP}"
          if !names.nil? and names.size > 0
            host_str = host_str+" "+names.join(" ")
          end
          ssh_config.puts host_str
          ssh_config.puts "  Hostname #{server.canonicalIP}"
          if !nat_ssh_host.nil? and server.canonicalIP != nat_ssh_host
            ssh_config.puts "  ProxyCommand ssh -W %h:%p #{nat_ssh_user}@#{nat_ssh_host}"
          end
          if timeout > 0
            ssh_config.puts "  ConnectTimeout #{timeout}"
          end

          ssh_config.puts "  User #{ssh_user}"
# XXX I'd rather add the host key to known_hosts, but Net::SSH is a little dumb
          ssh_config.puts "  StrictHostKeyChecking no"
          ssh_config.puts "  ServerAliveInterval 60"

          ssh_config.puts "  IdentityFile #{ssh_dir}/#{ssh_key_name}"
          if !File.exist?("#{ssh_dir}/#{ssh_key_name}")
            MU.log "#{server.mu_name} - ssh private key #{ssh_dir}/#{ssh_key_name} does not exist", MU::WARN
          end

          ssh_config.flock(File::LOCK_UN)
          ssh_config.chown(Etc.getpwnam(ssh_owner).uid, Etc.getpwnam(ssh_owner).gid)
        }
        MU.log "Wrote #{server.mu_name} ssh key to #{ssh_dir}/config", MU::DEBUG
        return "#{ssh_dir}/#{ssh_key_name}"
      }
    end

    # Clean an IP address out of ~/.ssh/known hosts
    # @param ip [String]: The IP to remove
    # @return [void]
    def self.removeIPFromSSHKnownHosts(ip, noop: false)
      return if ip.nil?
      sshdir = "#{MY_HOME}/.ssh"
      knownhosts = "#{sshdir}/known_hosts"

      if File.exist?(knownhosts) and File.open(knownhosts).read.match(/^#{Regexp.quote(ip)} /)
        MU.log "Expunging old #{ip} entry from #{knownhosts}", MU::NOTICE
        if !noop
          File.open(knownhosts, File::CREAT|File::RDWR, 0600) { |f|
            f.flock(File::LOCK_EX)
            newlines = Array.new
            f.readlines.each { |line|
              next if line.match(/^#{Regexp.quote(ip)} /)
              newlines << line
            }
            f.rewind
            f.truncate(0)
            f.puts(newlines)
            f.flush
            f.flock(File::LOCK_UN)
          }
        end
      end
    end

    # Clean a node's entries out of ~/.ssh/config
    # @param nodename [String]: The node's name
    # @return [void]
    def self.removeHostFromSSHConfig(nodename, noop: false)
      sshdir = "#{MY_HOME}/.ssh"
      sshconf = "#{sshdir}/config"

      if File.exist?(sshconf) and File.open(sshconf).read.match(/ #{nodename} /)
        MU.log "Expunging old #{nodename} entry from #{sshconf}", MU::DEBUG
        if !noop
          File.open(sshconf, File::CREAT|File::RDWR, 0600) { |f|
            f.flock(File::LOCK_EX)
            newlines = Array.new
            delete_block = false
            f.readlines.each { |line|
              if line.match(/^Host #{nodename}(\s|$)/)
                delete_block = true
              elsif line.match(/^Host /)
                delete_block = false
              end
              newlines << line if !delete_block
            }
            f.rewind
            f.truncate(0)
            f.puts(newlines)
            f.flush
            f.flock(File::LOCK_UN)
          }
        end
      end
    end

    # Evict ssh keys associated with a particular deploy from our ssh config
    # and key directory.
    # @param deploy_id [String]
    # @param noop [Boolean]
    def self.purgeDeployFromSSH(deploy_id, noop: false)
      myhome = Etc.getpwuid(Process.uid).dir
      sshdir = "#{myhome}/.ssh"
      sshconf = "#{sshdir}/config"
      ssharchive = "#{sshdir}/archive"

      Dir.mkdir(sshdir, 0700) if !Dir.exist?(sshdir) and !noop
      Dir.mkdir(ssharchive, 0700) if !Dir.exist?(ssharchive) and !noop

      keyname = "deploy-#{deploy_id}"
      if File.exist?("#{sshdir}/#{keyname}")
        MU.log "Moving #{sshdir}/#{keyname} to #{ssharchive}/#{keyname}"
        if !noop
          File.rename("#{sshdir}/#{keyname}", "#{ssharchive}/#{keyname}")
        end
      end
      if File.exist?(sshconf) and File.open(sshconf).read.match(/\/deploy\-#{deploy_id}$/)
        MU.log "Expunging #{deploy_id} from #{sshconf}"
        if !noop
          FileUtils.copy(sshconf, "#{ssharchive}/config-#{deploy_id}")
          File.open(sshconf, File::CREAT|File::RDWR, 0600) { |f|
            f.flock(File::LOCK_EX)
            newlines = Array.new
            delete_block = false
            f.readlines.each { |line|
              if line.match(/^Host #{deploy_id}\-/)
                delete_block = true
              elsif line.match(/^Host /)
                delete_block = false
              end
              newlines << line if !delete_block
            }
            f.rewind
            f.truncate(0)
            f.puts(newlines)
            f.flush
            f.flock(File::LOCK_UN)
          }
        end
      end
      # XXX refactor with above? They're similar, ish.
      hostsfile = "/etc/hosts"
      if File.open(hostsfile).read.match(/ #{deploy_id}\-/)
        if Process.uid == 0
          MU.log "Expunging traces of #{deploy_id} from #{hostsfile}"
          if !noop
            FileUtils.copy(hostsfile, "#{hostsfile}.cleanup-#{deploy_id}")
            File.open(hostsfile, File::CREAT|File::RDWR, 0644) { |f|
              f.flock(File::LOCK_EX)
              newlines = Array.new
              f.readlines.each { |line|
                newlines << line if !line.match(/ #{deploy_id}\-/)
              }
              f.rewind
              f.truncate(0)
              f.puts(newlines)
              f.flush
              f.flock(File::LOCK_UN)
            }
          end
        else
          MU.log "Residual /etc/hosts entries for #{deploy_id} must be removed by root user", MU::WARN
        end
      end

    end

    # Ensure that the Nagios configuration local to the MU master has been
    # updated, and make sure Nagios has all of the ssh keys it needs to tunnel
    # to client nodes.
    # @return [void]
    def self.syncMonitoringConfig(blocking = true)
      return if Etc.getpwuid(Process.uid).name != "root" or (MU.mu_user != "mu" and MU.mu_user != "root")
      parent_thread_id = Thread.current.object_id
      nagios_threads = []
      nagios_threads << Thread.new {
        MU.dupGlobals(parent_thread_id)
        realhome = Etc.getpwnam("nagios").dir
        [NAGIOS_HOME, "#{NAGIOS_HOME}/.ssh"].each { |dir|
          Dir.mkdir(dir, 0711) if !Dir.exist?(dir)
          File.chown(Etc.getpwnam("nagios").uid, Etc.getpwnam("nagios").gid, dir)
        }
        if realhome != NAGIOS_HOME and Dir.exist?(realhome) and !File.symlink?("#{realhome}/.ssh")
          File.rename("#{realhome}/.ssh", "#{realhome}/.ssh.#{$$}") if Dir.exist?("#{realhome}/.ssh")
          File.symlink("#{NAGIOS_HOME}/.ssh", Etc.getpwnam("nagios").dir+"/.ssh")
        end
        MU.log "Updating #{NAGIOS_HOME}/.ssh/config..."
        ssh_lock = File.new("#{NAGIOS_HOME}/.ssh/config.mu.lock", File::CREAT|File::TRUNC|File::RDWR, 0600)
        ssh_lock.flock(File::LOCK_EX)
        ssh_conf = File.new("#{NAGIOS_HOME}/.ssh/config.tmp", File::CREAT|File::TRUNC|File::RDWR, 0600)
        ssh_conf.puts "Host MU-MASTER localhost"
        ssh_conf.puts "  Hostname localhost"
        ssh_conf.puts "  User root"
        ssh_conf.puts "  IdentityFile #{NAGIOS_HOME}/.ssh/id_rsa"
        ssh_conf.puts "  StrictHostKeyChecking no"
        ssh_conf.close
        FileUtils.cp("#{Etc.getpwuid(Process.uid).dir}/.ssh/id_rsa", "#{NAGIOS_HOME}/.ssh/id_rsa")
        File.chown(Etc.getpwnam("nagios").uid, Etc.getpwnam("nagios").gid, "#{NAGIOS_HOME}/.ssh/id_rsa")
        threads = []

        parent_thread_id = Thread.current.object_id
        MU::MommaCat.listDeploys.sort.each { |deploy_id|
          begin
            # We don't want to use cached litter information here because this is also called by cleanTerminatedInstances.
            deploy = MU::MommaCat.getLitter(deploy_id)
            if deploy.ssh_key_name.nil? or deploy.ssh_key_name.empty?
              MU.log "Failed to extract ssh key name from #{deploy_id} in syncMonitoringConfig", MU::ERR if deploy.kittens.has_key?("servers")
              next
            end
            FileUtils.cp("#{Etc.getpwuid(Process.uid).dir}/.ssh/#{deploy.ssh_key_name}", "#{NAGIOS_HOME}/.ssh/#{deploy.ssh_key_name}")
            File.chown(Etc.getpwnam("nagios").uid, Etc.getpwnam("nagios").gid, "#{NAGIOS_HOME}/.ssh/#{deploy.ssh_key_name}")
            if deploy.kittens.has_key?("servers")
              deploy.kittens["servers"].values.each { |nodeclasses|
                nodeclasses.values.each { |nodes|
                  nodes.values.each { |server|
                    next if !server.cloud_desc
                    MU.dupGlobals(parent_thread_id)
                    threads << Thread.new {
                      MU::MommaCat.setThreadContext(deploy)
                      MU.log "Adding #{server.mu_name} to #{NAGIOS_HOME}/.ssh/config", MU::DEBUG
                      MU::Master.addHostToSSHConfig(
                          server,
                          ssh_dir: "#{NAGIOS_HOME}/.ssh",
                          ssh_conf: "#{NAGIOS_HOME}/.ssh/config.tmp",
                          ssh_owner: "nagios"
                      )
                      MU.purgeGlobals
                    }
                  }
                }
              }
            end
          rescue StandardError => e
            MU.log "#{e.inspect} while generating Nagios SSH config in #{deploy_id}", MU::ERR, details: e.backtrace
          end
        }
        threads.each { |t|
          t.join
        }
        ssh_lock.flock(File::LOCK_UN)
        ssh_lock.close
        File.chown(Etc.getpwnam("nagios").uid, Etc.getpwnam("nagios").gid, "#{NAGIOS_HOME}/.ssh/config.tmp")
        File.rename("#{NAGIOS_HOME}/.ssh/config.tmp", "#{NAGIOS_HOME}/.ssh/config")

        MU.log "Updating Nagios monitoring config, this may take a while..."
        output = nil
        if $MU_CFG and !$MU_CFG['master_runlist_extras'].nil?
          output = %x{#{MU::Groomer::Chef.chefclient} -o 'role[mu-master-nagios-only],#{$MU_CFG['master_runlist_extras'].join(",")}' 2>&1}
        else
          output = %x{#{MU::Groomer::Chef.chefclient} -o 'role[mu-master-nagios-only]' 2>&1}
        end

        if $?.exitstatus != 0
          MU.log "Nagios monitoring config update returned a non-zero exit code!", MU::ERR, details: output
        else
          MU.log "Nagios monitoring config update complete."
        end
      }

      if blocking
        nagios_threads.each { |t|
          t.join
        }
      end
    end

    # Recursively zip a directory
    # @param srcdir [String]
    # @param outfile [String]
    def self.zipDir(srcdir, outfile)
      require 'zip'
      ::Zip::File.open(outfile, ::Zip::File::CREATE) { |zipfile|
        addpath = Proc.new { |zip_path, parent_path|
          Dir.entries(parent_path).reject{ |d| [".", ".."].include?(d) }.each { |entry|
            src = File.join(parent_path, entry)
            dst = File.join(zip_path, entry).sub(/^\//, '')
            if File.directory?(src)
              addpath.call(dst, src)
            else
              zipfile.add(dst, src)
            end
          }
        }
        addpath.call("", srcdir)
      }
    end

    # Just list our block devices
    # @return [Array<String>]
    def self.listBlockDevices
      if File.executable?("/bin/lsblk")
        %x{/bin/lsblk -i -p -r -n | egrep ' disk( |$)'}.each_line.map { |l|
          l.chomp.sub(/ .*/, '')
        }
      else
        # XXX something dumber
        nil
      end
    end


    # Retrieve the UUID of a block device, if available
    # @param dev [String]
    def self.diskUUID(dev)
      realdev = MU::Cloud::AWS.hosted? ? MU::Cloud::AWS.realDevicePath(dev) : dev
      %x{/sbin/blkid #{realdev} -o export | grep ^UUID=}.chomp
    end

    # Determine whether we're running in an NVMe-enabled environment
    def self.nvme?
      if File.executable?("/bin/lsblk")
        %x{/bin/lsblk -i -p -r -n}.each_line { |l|
          return true if l =~ /^\/dev\/nvme\d/
        }
      else
        return true if File.exists?("/dev/nvme0n1")
      end
      false
    end


  end
end
