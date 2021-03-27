# Copyright:: Copyright (c) 2020 eGlobalTech, Inc., all rights reserved
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

  # MommaCat is in charge of managing metadata about resources we've created,
  # as well as orchestrating amongst them and bootstrapping nodes outside of
  # the normal synchronous deploy sequence invoked by *mu-deploy*.
  class MommaCat

    # Check a provided deploy key against our stored version. The instance has
    # in theory accessed a secret via S3 and encrypted it with the deploy's
    # public key. If it decrypts correctly, we assume this instance is indeed
    # one of ours.
    # @param ciphertext [String]: The text to decrypt.
    # return [Boolean]: Whether the provided text was encrypted with the correct key
    def authKey(ciphertext)
      if @private_key.nil? or @deploy_secret.nil?
        MU.log "Missing auth metadata, can't authorize node in authKey", MU::ERR
        return false
      end
      my_key = OpenSSL::PKey::RSA.new(@private_key)

      begin
        if my_key.private_decrypt(ciphertext).force_encoding("UTF-8").chomp == @deploy_secret.force_encoding("UTF-8").chomp
          MU.log "Matched ciphertext for #{MU.deploy_id}", MU::INFO
          return true
        else
          MU.log "Mis-matched ciphertext for #{MU.deploy_id}", MU::ERR
          return false
        end
      rescue OpenSSL::PKey::RSAError => e
        MU.log "Error decrypting provided ciphertext using private key from #{deploy_dir}/private_key: #{e.message}", MU::ERR, details: ciphertext
        return false
      end
    end

    # Run {MU::Cloud::Server#postBoot} and {MU::Cloud::Server#groom} on a node.
    # @param cloud_id [OpenStruct]: The cloud provider's identifier for this node.
    # @param name [String]: The MU resource name of the node being created.
    # @param mu_name [String]: The full #{MU::MommaCat.getResourceName} name of the server we're grooming, if it's been initialized already.
    # @param type [String]: The type of resource that created this node (either *server* or *serverpool*).
    def groomNode(cloud_id, name, type, mu_name: nil, reraise_fail: false, sync_wait: true)
      if cloud_id.nil?
        raise GroomError, "MU::MommaCat.groomNode requires a {MU::Cloud::Server} object"
      end
      if name.nil? or name.empty?
        raise GroomError, "MU::MommaCat.groomNode requires a resource name"
      end
      if type.nil? or type.empty?
        raise GroomError, "MU::MommaCat.groomNode requires a resource type"
      end

      if !MU::MommaCat.lock(cloud_id+"-mommagroom", true)
        MU.log "Instance #{cloud_id} on #{MU.deploy_id} (#{type}: #{name}) is already being groomed, ignoring this extra request.", MU::NOTICE
        MU::MommaCat.unlockAll
        if !MU::MommaCat.locks.nil? and MU::MommaCat.locks.size > 0
          puts "------------------------------"
          puts "Open flock() locks:"
          pp MU::MommaCat.locks
          puts "------------------------------"
        end
        return
      end
      loadDeploy

      # XXX this is to stop Net::SSH from killing our entire stack when it
      # throws an exception. See ECAP-139 in JIRA. Far as we can tell, it's
      # just not entirely thread safe.
      Thread.handle_interrupt(Net::SSH::Disconnect => :never) {
        begin
          Thread.handle_interrupt(Net::SSH::Disconnect => :immediate) {
            MU.log "(Probably harmless) Caught a Net::SSH::Disconnect in #{Thread.current.inspect}", MU::DEBUG, details: Thread.current.backtrace
          }
        ensure
        end
      }

      if @original_config[type+"s"].nil?
        raise GroomError, "I see no configured resources of type #{type} (bootstrap request for #{name} on #{@deploy_id})"
      end
      kitten = nil

      kitten = findLitterMate(type: "server", name: name, mu_name: mu_name, cloud_id: cloud_id)
      if !kitten.nil?
        MU.log "Re-grooming #{mu_name}", details: kitten.deploydata
      else
        first_groom = true
        @original_config[type+"s"].each { |svr|
          if svr['name'] == name
            svr["instance_id"] = cloud_id

            # This will almost always be true in server pools, but lets be safe. Somewhat problematic because we are only
            # looking at deploy_id, but we still know this is our DNS record and not a custom one.
            if svr['dns_records'] && !svr['dns_records'].empty?
              svr['dns_records'].each { |dnsrec|
                if dnsrec.has_key?("name") && dnsrec['name'].start_with?(MU.deploy_id.downcase)
                  MU.log "DNS record for #{MU.deploy_id.downcase}, #{name} is probably wrong, deleting", MU::WARN, details: dnsrec
                  dnsrec.delete('name')
                  dnsrec.delete('target')
                end
              }
            end

            kitten = MU::Cloud::Server.new(mommacat: self, kitten_cfg: svr, cloud_id: cloud_id)
            mu_name = kitten.mu_name if mu_name.nil?
            MU.log "Grooming #{mu_name} for the first time", details: svr
            break
          end
        }
      end

      begin
        # This is a shared lock with MU::Cloud::AWS::Server.create, to keep from
        # stomping on synchronous deploys that are still running. This
        # means we're going to wait here if this instance is still being
        # bootstrapped by "regular" means.
        if !MU::MommaCat.lock(cloud_id+"-create", true)
          MU.log "#{mu_name} is still in mid-creation, skipping", MU::NOTICE
          MU::MommaCat.unlockAll
          if !MU::MommaCat.locks.nil? and MU::MommaCat.locks.size > 0
            puts "------------------------------"
            puts "Open flock() locks:"
            pp MU::MommaCat.locks
            puts "------------------------------"
          end
          return
        end
        MU::MommaCat.unlock(cloud_id+"-create")

        if !kitten.postBoot(cloud_id)
          MU.log "#{mu_name} is already being groomed, skipping", MU::NOTICE
          MU::MommaCat.unlockAll
          if !MU::MommaCat.locks.nil? and MU::MommaCat.locks.size > 0
            puts "------------------------------"
            puts "Open flock() locks:"
            pp MU::MommaCat.locks
            puts "------------------------------"
          end
          return
        end

        # This is a shared lock with MU::Deploy.createResources, simulating the
        # thread logic that tells MU::Cloud::AWS::Server.deploy to wait until
        # its dependencies are ready. We don't, for example, want to start
        # deploying if we rely on an RDS instance that isn't ready yet. We can
        # release this immediately, once we successfully grab it.
        MU::MommaCat.lock("#{kitten.cloudclass.name}_#{kitten.config["name"]}-dependencies")
        MU::MommaCat.unlock("#{kitten.cloudclass.name}_#{kitten.config["name"]}-dependencies")

        kitten.groom
      rescue StandardError => e
        MU::MommaCat.unlockAll
        if e.class.name != "MU::Cloud::AWS::Server::BootstrapTempFail" and !File.exist?(deploy_dir+"/.cleanup."+cloud_id) and !File.exist?(deploy_dir+"/.cleanup")
          MU.log "Grooming FAILED for #{kitten.mu_name} (#{e.inspect})", MU::ERR, details: e.backtrace
          sendAdminSlack("Grooming FAILED for `#{kitten.mu_name}` with `#{e.message}` :crying_cat_face:", msg: e.backtrace.join("\n"))
          sendAdminMail("Grooming FAILED for #{kitten.mu_name} on #{MU.appname} \"#{MU.handle}\" (#{MU.deploy_id})",
            msg: e.inspect,
            data: e.backtrace,
            debug: true
          )
          raise e if reraise_fail
        else
          MU.log "Grooming of #{kitten.mu_name} interrupted by cleanup or planned reboot"
        end
        return
      end

      if !@deployment['servers'].nil? and !sync_wait
        syncLitter(@deployment["servers"].keys, triggering_node: kitten)
      end
      MU::MommaCat.unlock(cloud_id+"-mommagroom")
      if MU.myCloud == "AWS"
        MU::Cloud::AWS.openFirewallForClients # XXX add the other clouds, or abstract
      end
      MU::MommaCat.getLitter(MU.deploy_id)
      MU::Master.syncMonitoringConfig(false)
      MU.log "Grooming complete for '#{name}' mu_name on \"#{MU.handle}\" (#{MU.deploy_id})"
      FileUtils.touch(MU.dataDir+"/deployments/#{MU.deploy_id}/#{name}_done.txt")
      MU::MommaCat.unlockAll
      if first_groom
        sendAdminSlack("Grooming complete for #{mu_name} :heart_eyes_cat:")
        sendAdminMail("Grooming complete for '#{name}' (#{mu_name}) on deploy \"#{MU.handle}\" (#{MU.deploy_id})")
      end
      return
    end

    @cleanup_threads = []

    # Iterate over all known deployments and look for instances that have been
    # terminated, but not yet cleaned up, then clean them up.
    def self.cleanTerminatedInstances(debug = false)
      loglevel = debug ? MU::NOTICE : MU::DEBUG
      MU::MommaCat.lock("clean-terminated-instances", false, true)
      MU.log "Checking for harvested instances in need of cleanup", loglevel
      parent_thread_id = Thread.current.object_id
      purged = 0

      MU::MommaCat.listDeploys.each { |deploy_id|
        next if File.exist?(deploy_dir(deploy_id)+"/.cleanup")
        MU.log "Checking for dead wood in #{deploy_id}", loglevel
        need_reload = false
        @cleanup_threads << Thread.new {
          MU.dupGlobals(parent_thread_id)
          Thread.current.thread_variable_set("cleanTerminatedInstances", deploy_id)
          deploy = MU::MommaCat.getLitter(deploy_id, set_context_to_me: true)
          purged_this_deploy = 0
            MU.log "#{deploy_id} has some kittens in it", loglevel, details: deploy.kittens.keys
          if deploy.kittens.has_key?("servers")
            MU.log "#{deploy_id} has some servers declared", loglevel, details: deploy.object_id
            deploy.kittens["servers"].values.each { |nodeclasses|
              nodeclasses.each_pair { |nodeclass, servers|
                deletia = []
                MU.log "Checking status of servers under '#{nodeclass}'", loglevel, details: servers.keys
                servers.each_pair { |mu_name, server|
                  server.describe
                  if !server.cloud_id
                    MU.log "Checking for presence of instance '#{mu_name}', but unable to fetch its cloud_id", MU::WARN, server.class.name
                    pp servers.keys
                  elsif !server.active?
                    next if File.exist?(deploy_dir(deploy_id)+"/.cleanup-"+server.cloud_id)
                    deletia << mu_name
                    need_reload = true
                    MU.log "Cleaning up metadata for #{server} (#{nodeclass}), formerly #{server.cloud_id}, which appears to have been terminated", MU::NOTICE
                    begin
                      server.destroy
                      deploy.sendAdminMail("Retired metadata for terminated node #{mu_name}")
                      deploy.sendAdminSlack("Retired metadata for terminated node `#{mu_name}`")
                    rescue StandardError => e
                      MU.log "Saw #{e.message} while retiring #{mu_name}", MU::ERR, details: e.backtrace
                      next
                    end
                    MU.log "Cleanup of metadata for #{server} (#{nodeclass}), formerly #{server.cloud_id} complete", MU::NOTICE
                    purged = purged + 1
                    purged_this_deploy = purged_this_deploy + 1
                  end
                }
                deletia.each { |mu_name|
                  servers.delete(mu_name)
                }
                if purged_this_deploy > 0
                  # XXX triggering_node needs to take more than one node name
                  deploy.syncLitter(servers.keys, triggering_node: deletia.first)
                end
              }
            }
          end
          if need_reload
            MU.log "Saving modified deploy #{deploy_id}", loglevel
            deploy.save!
            MU::MommaCat.getLitter(deploy_id)
          end
          MU.purgeGlobals
        }
      }
      @cleanup_threads.each { |t|
        t.join
      }
      MU.log "cleanTerminatedInstances threads complete", loglevel
      MU::MommaCat.unlock("clean-terminated-instances", true)
      @cleanup_threads = []

      if purged > 0
        if MU.myCloud == "AWS"
          MU::Cloud::AWS.openFirewallForClients # XXX add the other clouds, or abstract
        end
        MU::Master.syncMonitoringConfig
        GC.start
      end
      MU.log "cleanTerminatedInstances returning", loglevel
    end

    # Path to the log file used by the Momma Cat daemon
    # @return [String]
    def self.daemonLogFile
      base = (Process.uid == 0 and !MU.localOnly) ? "/var" : MU.dataDir
      "#{base}/log/mu-momma-cat.log"
    end

    # Path to the PID file used by the Momma Cat daemon
    # @return [String]
    def self.daemonPidFile(root = false)
      base = ((Process.uid == 0 or root) and !MU.localOnly) ? "/var" : MU.dataDir
      "#{base}/run/mommacat.pid"
    end

		# Start the Momma Cat daemon and return the exit status of the command used
    # @return [Integer]
    def self.start
      if MU.inGem? and MU.muCfg['disable_mommacat']
        return
      end
      base = (Process.uid == 0 and !MU.localOnly) ? "/var" : MU.dataDir
      [base, "#{base}/log", "#{base}/run"].each { |dir|
       if !Dir.exist?(dir)
          MU.log "Creating #{dir}"
          Dir.mkdir(dir)
        end
      }
      if (Process.uid != 0 and
           (!$MU_CFG['overridden_keys'] or !$MU_CFG['overridden_keys'].include?("mommacat_port")) and
            status(true)
         ) or status
        return 0
      end
    
      File.unlink(daemonPidFile) if File.exists?(daemonPidFile)
      MU.log "Starting Momma Cat on port #{MU.mommaCatPort}, logging to #{daemonLogFile}, PID file #{daemonPidFile}"
      origdir = Dir.getwd
      Dir.chdir(MU.myRoot+"/modules")

      # XXX what's the safest way to find the 'bundle' executable in both gem and non-gem installs?
      if MU.inGem?
        cmd = %Q{thin --threaded --daemonize --port #{MU.mommaCatPort} --pid #{daemonPidFile} --log #{daemonLogFile} --ssl --ssl-key-file #{MU.muCfg['ssl']['key']} --ssl-cert-file #{MU.muCfg['ssl']['cert']} --ssl-disable-verify --tag mu-momma-cat -R mommacat.ru start}
      else
        cmd = %Q{bundle exec thin --threaded --daemonize --port #{MU.mommaCatPort} --pid #{daemonPidFile} --log #{daemonLogFile} --ssl --ssl-key-file #{MU.muCfg['ssl']['key']} --ssl-cert-file #{MU.muCfg['ssl']['cert']} --ssl-disable-verify --tag mu-momma-cat -R mommacat.ru start}
      end

      MU.log cmd, MU::NOTICE

      retries = 0
      begin
        output = %x{#{cmd}}
        sleep 1
        retries += 1
        if retries >= 10
          MU.log "MommaCat failed to start (command was #{cmd}, working directory #{MU.myRoot}/modules)", MU::WARN, details: output
          pp caller
          return $?.exitstatus
        end
      end while !status

      Dir.chdir(origdir)
    
      if $?.exitstatus != 0
        exit 1
      end

      return $?.exitstatus
    end

    @@notified_on_pid = {}

    # Return true if the Momma Cat daemon appears to be running
    # @return [Boolean]
    def self.status(root = false)
      if MU.inGem? and MU.muCfg['disable_mommacat']
        return true
      end
      if File.exist?(daemonPidFile(root))
        pid = File.read(daemonPidFile(root)).chomp.to_i
        begin
          Process.getpgid(pid)
          MU.log "Momma Cat running with pid #{pid.to_s}", (@@notified_on_pid[pid] ? MU::DEBUG : MU::INFO) # shush
          @@notified_on_pid[pid] = true
          return true
        rescue Errno::ESRCH
        end
      end
      MU.log "Momma Cat daemon not running", MU::NOTICE, details: daemonPidFile(root)
      false
    end
    
		# Stop the Momma Cat daemon, if it's running
    def self.stop
      if File.exist?(daemonPidFile)
        pid = File.read(daemonPidFile).chomp.to_i
        MU.log "Stopping Momma Cat with pid #{pid.to_s}"
        Process.kill("INT", pid)
        killed = false
        begin
          Process.getpgid(pid)
          sleep 1
        rescue Errno::ESRCH
          killed = true
        end while killed
        MU.log "Momma Cat with pid #{pid.to_s} stopped", MU::DEBUG, details: daemonPidFile
    
        begin
          File.unlink(daemonPidFile)
        rescue Errno::ENOENT
        end
      end
    end

		# (Re)start the Momma Cat daemon and return the exit status of the start command
    # @return [Integer]
    def self.restart
      stop
      start
    end

  end #class
end #module
