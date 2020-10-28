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
    @myhome = Etc.getpwuid(Process.uid).dir
    @nagios_home = "/opt/mu/var/nagios_user_home"
    @locks = Hash.new
    @deploy_cache = Hash.new

    # Return a {MU::MommaCat} instance for an existing deploy. Use this instead
    # of using #initialize directly to avoid loading deploys multiple times or
    # stepping on the global context for the deployment you're really working
    # on..
    # @param deploy_id [String]: The deploy ID of the deploy to load.
    # @param set_context_to_me [Boolean]: Whether new MommaCat objects should overwrite any existing per-thread global deploy variables.
    # @param use_cache [Boolean]: If we have an existing object for this deploy, use that
    # @return [MU::MommaCat]
    def self.getLitter(deploy_id, set_context_to_me: false, use_cache: true)
      if deploy_id.nil? or deploy_id.empty?
        raise MuError, "Cannot fetch a deployment without a deploy_id"
      end

# XXX this caching may be harmful, causing stale resource objects to stick
# around. Have we fixed this? Sort of. Bad entries seem to have no kittens,
# so force a reload if we see that. That's probably not the root problem.
      littercache = nil
      begin
        @@litter_semaphore.synchronize {
          littercache = @@litters.dup
        }
        if littercache[deploy_id] and @@litters_loadtime[deploy_id]
          deploy_root = File.expand_path(MU.dataDir+"/deployments")
          this_deploy_dir = deploy_root+"/"+deploy_id
          if File.exist?("#{this_deploy_dir}/deployment.json")
            lastmod = File.mtime("#{this_deploy_dir}/deployment.json")
            if lastmod > @@litters_loadtime[deploy_id]
              MU.log "Deployment metadata for #{deploy_id} was modified on disk, reload", MU::NOTICE
              use_cache = false
            end
         end
        end
      rescue ThreadError => e
        # already locked by a parent caller and this is a read op, so this is ok
        raise e if !e.message.match(/recursive locking/)
        littercache = @@litters.dup
      end

      if !use_cache or littercache[deploy_id].nil?
        need_gc = !littercache[deploy_id].nil?
        newlitter = MU::MommaCat.new(deploy_id, set_context_to_me: set_context_to_me)
        # This, we have to synchronize, as it's a write
        @@litter_semaphore.synchronize {
          @@litters[deploy_id] = newlitter
          @@litters_loadtime[deploy_id] = Time.now
        }
        GC.start if need_gc
      elsif set_context_to_me
        MU::MommaCat.setThreadContext(@@litters[deploy_id])
      end
      return @@litters[deploy_id]
#     MU::MommaCat.new(deploy_id, set_context_to_me: set_context_to_me)
    end

    # List the currently held flock() locks.
    def self.trapSafeLocks;
      @locks
    end
    # List the currently held flock() locks.
    def self.locks;
      @lock_semaphore.synchronize {
        @locks
      }
    end


    # Overwrite this deployment's configuration with a new version. Save the
    # previous version as well.
    # @param new_conf [Hash]: A new configuration, fully resolved by {MU::Config}
    def updateBasketofKittens(new_conf, skip_validation: false, new_metadata: nil, save_now: false)
      loadDeploy
      if new_conf == @original_config
        return
      end

      scrub_with = nil

      # Make sure the new config that we were just handed resolves and makes
      # sense
      if !skip_validation
        f = Tempfile.new(@deploy_id)
        f.write JSON.parse(JSON.generate(new_conf)).to_yaml
        conf_engine = MU::Config.new(f.path) # will throw an exception if it's bad, adoption should catch this and cope reasonably
        scrub_with = conf_engine.config
        f.close
      end

      backup = "#{deploy_dir}/basket_of_kittens.json.#{Time.now.to_i.to_s}"
      MU.log "Saving previous config of #{@deploy_id} to #{backup}"
      config = File.new(backup, File::CREAT|File::TRUNC|File::RDWR, 0600)
      config.flock(File::LOCK_EX)
      config.puts JSON.pretty_generate(@original_config)
      config.flock(File::LOCK_UN)
      config.close

      @original_config = new_conf.clone

      MU::Cloud.resource_types.each_pair { |res_type, attrs|
        next if !@deployment.has_key?(attrs[:cfg_plural])
        deletia = []
# existing_deploys
        @deployment[attrs[:cfg_plural]].each_pair { |res_name, data|
          orig_cfg = findResourceConfig(attrs[:cfg_plural], res_name, (scrub_with || @original_config))

          if orig_cfg.nil? and (!data['mu_name'] or data['mu_name'] =~ /^#{Regexp.quote(@deploy_id)}/)
            MU.log "#{res_type} #{res_name} no longer configured, will remove deployment metadata", MU::NOTICE, details: data
            deletia << res_name
          end
        }
        @deployment[attrs[:cfg_plural]].reject! { |k, v| deletia.include?(k) }
      }

      if save_now
        save!
        MU.log "New config saved to #{deploy_dir}/basket_of_kittens.json"
      end
    end

    @lock_semaphore = Mutex.new
    # Release all flock() locks held by the current thread.
    def self.unlockAll
      if !@locks.nil? and !@locks[Thread.current.object_id].nil?
        # Work from a copy so we can iterate without worrying about contention
        # in lock() or unlock(). We can't just wrap our iterator block in a
        # semaphore here, because we're calling another method that uses the
        # same semaphore.
        @lock_semaphore.synchronize {
          delete_list = []
          @locks[Thread.current.object_id].keys.each { |id|
            MU.log "Releasing lock on #{deploy_dir(MU.deploy_id)}/locks/#{id}.lock (thread #{Thread.current.object_id})", MU::DEBUG
            begin
              @locks[Thread.current.object_id][id].flock(File::LOCK_UN)
              @locks[Thread.current.object_id][id].close
            rescue IOError => e
              MU.log "Got #{e.inspect} unlocking #{id} on #{Thread.current.object_id}", MU::WARN
            end
            delete_list << id
          }
          # We do this here because we can't mangle a Hash while we're iterating
          # over it.
          delete_list.each { |id|
            @locks[Thread.current.object_id].delete(id)
          }
          if @locks[Thread.current.object_id].size == 0
            @locks.delete(Thread.current.object_id)
          end
        }
      end
    end

    # Create/hold a flock() lock.
    # @param id [String]: The lock identifier to release.
    # @param nonblock [Boolean]: Whether to block while waiting for the lock. In non-blocking mode, we simply return false if the lock is not available.
    # return [false, nil]
    def self.lock(id, nonblock = false, global = false, retries: 0, deploy_id: MU.deploy_id)
      raise MuError, "Can't pass a nil id to MU::MommaCat.lock" if id.nil?

      if !global
        lockdir = "#{deploy_dir(deploy_id)}/locks"
      else
        lockdir = File.expand_path(MU.dataDir+"/locks")
      end

      if !Dir.exist?(lockdir)
        MU.log "Creating #{lockdir}", MU::DEBUG
        Dir.mkdir(lockdir, 0700)
      end
      nonblock = true if retries > 0

      @lock_semaphore.synchronize {
        if @locks[Thread.current.object_id].nil?
          @locks[Thread.current.object_id] = Hash.new
        end

        @locks[Thread.current.object_id][id] = File.open("#{lockdir}/#{id}.lock", File::CREAT|File::RDWR, 0600)
      }

      MU.log "Getting a lock on #{lockdir}/#{id}.lock (thread #{Thread.current.object_id})...", MU::DEBUG, details: caller
      show_relevant = Proc.new {
        @lock_semaphore.synchronize {
          @locks.each_pair { |thread_id, lock|
            lock.each_pair { |lockid, lockpath|
              if lockid == id
                thread = Thread.list.select { |t| t.object_id == thread_id }.first
                if thread.object_id != Thread.current.object_id
                  MU.log "#{thread_id} sitting on #{id}", MU::WARN, thread.backtrace
                end
              end
            }
          }
        }
      }
      begin
        if nonblock
          if !@locks[Thread.current.object_id][id].flock(File::LOCK_EX|File::LOCK_NB)
            if retries > 0
              success = false
              MU.retrier([], loop_if: Proc.new { !success }, loop_msg: "Waiting for lock on #{lockdir}/#{id}.lock...", max: retries) { |cur_retries, _wait|
                success = @locks[Thread.current.object_id][id].flock(File::LOCK_EX|File::LOCK_NB)
                if !success and cur_retries > 0 and (cur_retries % 3) == 0
                  show_relevant.call(cur_retries)
                end
              }
              show_relevant.call(cur_retries) if !success
              return success
            else
              return false
            end
          end
        else
          @locks[Thread.current.object_id][id].flock(File::LOCK_EX)
        end
      rescue IOError
        raise MU::BootstrapTempFail, "Interrupted waiting for lock on thread #{Thread.current.object_id}, probably just a node rebooting as part of a synchronous install"
      end
      MU.log "Lock on #{lockdir}/#{id}.lock on thread #{Thread.current.object_id} acquired", MU::DEBUG
      return true
    end

    # Release a flock() lock.
    # @param id [String]: The lock identifier to release.
    def self.unlock(id, global = false, deploy_id: MU.deploy_id)
      raise MuError, "Can't pass a nil id to MU::MommaCat.unlock" if id.nil?
      lockdir = nil
      if !global
        lockdir = "#{deploy_dir(deploy_id)}/locks"
      else
        lockdir = File.expand_path(MU.dataDir+"/locks")
      end
      @lock_semaphore.synchronize {
        return if @locks.nil? or @locks[Thread.current.object_id].nil? or @locks[Thread.current.object_id][id].nil?
      }
      MU.log "Releasing lock on #{lockdir}/#{id}.lock (thread #{Thread.current.object_id})", MU::DEBUG
      begin
        @locks[Thread.current.object_id][id].flock(File::LOCK_UN)
        @locks[Thread.current.object_id][id].close
        if !@locks[Thread.current.object_id].nil?
          @locks[Thread.current.object_id].delete(id)
        end
        if @locks[Thread.current.object_id].size == 0
          @locks.delete(Thread.current.object_id)
        end
      rescue IOError => e
        MU.log "Got #{e.inspect} unlocking #{id} on #{Thread.current.object_id}", MU::WARN
      end
    end

    # Remove a deployment's metadata.
    # @param deploy_id [String]: The deployment identifier to remove.
    def self.purge(deploy_id)
      if deploy_id.nil? or deploy_id.empty?
        raise MuError, "Got nil deploy_id in MU::MommaCat.purge"
      end
      # XXX archiving is better than annihilating
      path = File.expand_path(MU.dataDir+"/deployments")
      if Dir.exist?(path+"/"+deploy_id)
        unlockAll
        MU.log "Purging #{path}/#{deploy_id}" if File.exist?(path+"/"+deploy_id+"/deployment.json")

        FileUtils.rm_rf(path+"/"+deploy_id, :secure => true)
      end
      if File.exist?(path+"/unique_ids")
        File.open(path+"/unique_ids", File::CREAT|File::RDWR, 0600) { |f|
          newlines = []
          f.flock(File::LOCK_EX)
          f.readlines.each { |line|
            newlines << line if !line.match(/:#{deploy_id}$/)
          }
          f.rewind
          f.truncate(0)
          f.puts(newlines)
          f.flush
          f.flock(File::LOCK_UN)
        }
      end
    end

    # Remove the metadata of the currently loaded deployment.
    def purge!
      MU::MommaCat.purge(MU.deploy_id)
    end

    # Return a list of all currently active deploy identifiers.
    # @return [Array<String>]
    def self.listDeploys
      return [] if !Dir.exist?("#{MU.dataDir}/deployments")
      deploys = []
      Dir.entries("#{MU.dataDir}/deployments").reverse_each { |muid|
        next if !Dir.exist?("#{MU.dataDir}/deployments/#{muid}") or muid == "." or muid == ".."
        deploys << muid
      }
      return deploys
    end

    # Return a list of all nodes in all deployments. Does so without loading
    # deployments fully.
    # @return [Hash]
    def self.listAllNodes
      nodes = Hash.new
      MU::MommaCat.deploy_struct_semaphore.synchronize {
        MU::MommaCat.listDeploys.each { |deploy|
          if !Dir.exist?(MU::MommaCat.deploy_dir(deploy)) or
              !File.size?("#{MU::MommaCat.deploy_dir(deploy)}/deployment.json")
            MU.log "Didn't see deployment metadata for '#{deploy}'", MU::WARN
            next
          end
          data = File.open("#{MU::MommaCat.deploy_dir(deploy)}/deployment.json", File::RDONLY)
          MU.log "Getting lock to read #{MU::MommaCat.deploy_dir(deploy)}/deployment.json", MU::DEBUG
          data.flock(File::LOCK_EX)
          begin
            deployment = JSON.parse(File.read("#{MU::MommaCat.deploy_dir(deploy)}/deployment.json"))
            deployment["deploy_id"] = deploy
            if deployment.has_key?("servers")
              deployment["servers"].each_key { |nodeclass|
                deployment["servers"][nodeclass].each_pair { |mu_name, metadata|
                  nodes[mu_name] = metadata
                }
              }
            end
          rescue JSON::ParserError => e
            MU.log "JSON parse failed on #{MU::MommaCat.deploy_dir(deploy)}/deployment.json", MU::ERR, details: e.message
          end
          data.flock(File::LOCK_UN)
          data.close
        }
      }
      return nodes
    end

    # @return [String]: The Mu Master filesystem directory holding metadata for the current deployment
    def deploy_dir
      MU::MommaCat.deploy_dir(@deploy_id)
    end

    # Locate and return the deploy, if any, which matches the provided origin
    # description
    # @param origin [Hash]
    def self.findMatchingDeploy(origin)
      MU::MommaCat.listDeploys.each { |deploy_id|
        o_path = deploy_dir(deploy_id)+"/origin.json"
        next if !File.exist?(o_path)
        this_origin = JSON.parse(File.read(o_path))
        if origin == this_origin
          MU.log "Deploy #{deploy_id} matches origin hash, loading", details: origin
          return MU::MommaCat.new(deploy_id)
        end
      }
      nil
    end

    # Synchronize all in-memory information related to this to deployment to
    # disk.
    # @param triggering_node [MU::Cloud::Server]: If we're being triggered by the addition/removal/update of a node, this allows us to notify any sibling or dependent nodes of changes
    # @param force [Boolean]: Save even if +no_artifacts+ is set
    # @param origin [Hash]: Optional blob of data indicating how this deploy was created
    def save!(triggering_node = nil, force: false, origin: nil)

      return if @no_artifacts and !force

      MU::MommaCat.deploy_struct_semaphore.synchronize {
        MU.log "Saving deployment #{MU.deploy_id}", MU::DEBUG

        if !Dir.exist?(deploy_dir)
          MU.log "Creating #{deploy_dir}", MU::DEBUG
          Dir.mkdir(deploy_dir, 0700)
        end

        writeFile("origin.json", JSON.pretty_generate(origin)) if !origin.nil?
        writeFile("private_key", @private_key) if !@private_key.nil?
        writeFile("public_key", @public_key) if !@public_key.nil?

        if !@deployment.nil? and @deployment.size > 0
          @deployment['handle'] = MU.handle if @deployment['handle'].nil? and !MU.handle.nil?
          [:public_key, :timestamp, :seed, :appname, :handle, :ssh_public_key].each { |var|
            value = instance_variable_get(("@"+var.to_s).to_sym)
            @deployment[var.to_s] = value if value
          }
          
          begin
            # XXX doing this to trigger JSON errors before stomping the stored
            # file...
            JSON.pretty_generate(@deployment, max_nesting: false)
            deploy = File.new("#{deploy_dir}/deployment.json", File::CREAT|File::TRUNC|File::RDWR, 0600)
            MU.log "Getting lock to write #{deploy_dir}/deployment.json", MU::DEBUG
            deploy.flock(File::LOCK_EX)
            deploy.puts JSON.pretty_generate(@deployment, max_nesting: false)
          rescue JSON::NestingError => e
            MU.log e.inspect, MU::ERR, details: @deployment
            raise MuError, "Got #{e.message} trying to save deployment"
          rescue Encoding::UndefinedConversionError => e
            MU.log e.inspect, MU::ERR, details: @deployment
            raise MuError, "Got #{e.message} at #{e.error_char.dump} (#{e.source_encoding_name} => #{e.destination_encoding_name}) trying to save deployment"
          end
          deploy.flock(File::LOCK_UN)
          deploy.close
          @need_deploy_flush = false
          @last_modified = nil
          MU::MommaCat.updateLitter(@deploy_id, self)
        end

        if !@original_config.nil? and @original_config.is_a?(Hash)
          writeFile("basket_of_kittens.json", JSON.pretty_generate(MU::Config.manxify(@original_config)))
        end

        writeFile("node_ssh.key", @ssh_private_key) if !@ssh_private_key.nil?
        writeFile("node_ssh.pub", @ssh_public_key) if !@ssh_public_key.nil?
        writeFile("ssh_key_name", @ssh_key_name) if !@ssh_key_name.nil?
        writeFile("environment_name", @environment) if !@environment.nil?
        writeFile("deploy_secret", @deploy_secret) if !@deploy_secret.nil?

        if !@secrets.nil?
          secretdir = "#{deploy_dir}/secrets"
          if !Dir.exist?(secretdir)
            MU.log "Creating #{secretdir}", MU::DEBUG
            Dir.mkdir(secretdir, 0700)
          end
          @secrets.each_pair { |type, servers|
            servers.each_pair { |server, svr_secret|
              writeFile("secrets/#{type}.#{server}", svr_secret)
            }
          }
        end
      }

      # Update groomer copies of this metadata
      syncLitter(@deployment['servers'].keys, triggering_node: triggering_node, save_only: true) if @deployment.has_key?("servers")
    end

    # Read all of our +deployment.json+ files in and stick them in a hash. Used
    # by search routines that just need to skim this data without loading
    # entire {MU::MommaCat} objects.
    def self.cacheDeployMetadata(deploy_id = nil, use_cache: false)
      deploy_root = File.expand_path(MU.dataDir+"/deployments")
      MU::MommaCat.deploy_struct_semaphore.synchronize {
        @@deploy_cache ||= {}
        return if !Dir.exist?(deploy_root)

        Dir.entries(deploy_root).each { |deploy|
          this_deploy_dir = deploy_root+"/"+deploy
          this_deploy_file = this_deploy_dir+"/deployment.json"

          if deploy == "." or deploy == ".." or !Dir.exist?(this_deploy_dir) or
             (deploy_id and deploy_id != deploy) or
             !File.size?(this_deploy_file) or
             (use_cache and @@deploy_cache[deploy] and @@deploy_cache[deploy]['mtime'] == File.mtime(this_deploy_file))
            next
          end

          @@deploy_cache[deploy] ||= {}

          MU.log "Caching deploy #{deploy}", MU::DEBUG
          lock = File.open(this_deploy_file, File::RDONLY)
          lock.flock(File::LOCK_EX)
          @@deploy_cache[deploy]['mtime'] = File.mtime(this_deploy_file)

          begin
            @@deploy_cache[deploy]['data'] = JSON.parse(File.read(this_deploy_file))
            next if @@deploy_cache[deploy]['data'].nil?
            # Populate some generable entries that should be in the deploy
            # data. Also, bounce out if we realize we've found exactly what
            # we needed already.
            MU::Cloud.resource_types.values.each { |attrs|

              next if @@deploy_cache[deploy]['data'][attrs[:cfg_plural]].nil?
              if attrs[:has_multiples]
                @@deploy_cache[deploy]['data'][attrs[:cfg_plural]].each_pair { |node_class, nodes|
                  next if nodes.nil? or !nodes.is_a?(Hash)
                  nodes.each_pair { |nodename, data|
                    next if !data.is_a?(Hash)
                    data['#MU_NODE_CLASS'] ||= node_class
                    data['#MU_NAME'] ||= nodename
                    data["cloud"] ||= MU::Config.defaultCloud
                  }
                }
              end
            }
          rescue JSON::ParserError
            raise MuError, "JSON parse failed on #{this_deploy_file}\n\n"+File.read(this_deploy_file)
          ensure
            lock.flock(File::LOCK_UN)
            lock.close
          end
        }
      }

      @@deploy_cache
    end

    # Get the deploy directory
    # @param deploy_id [String]
    # @return [String]
    def self.deploy_dir(deploy_id)
      raise MuError, "deploy_dir must get a deploy_id if called as class method (from #{caller[0]}; #{caller[1]})" if deploy_id.nil?
# XXX this will blow up if someone sticks MU in /
      path = File.expand_path(MU.dataDir+"/deployments")
      if !Dir.exist?(path)
        MU.log "Creating #{path}", MU::DEBUG
        Dir.mkdir(path, 0700)
      end
      path = path+"/"+deploy_id
      return path
    end

    # Does the deploy with the given id exist?
    # @param deploy_id [String]
    # @return [String]
    def self.deploy_exists?(deploy_id)
      if deploy_id.nil? or deploy_id.empty?
        MU.log "Got nil deploy_id in MU::MommaCat.deploy_exists?", MU::WARN
        return
      end
      path = File.expand_path(MU.dataDir+"/deployments")
      if !Dir.exist?(path)
        Dir.mkdir(path, 0700)
      end
      deploy_path = File.expand_path(path+"/"+deploy_id)
      return Dir.exist?(deploy_path)
    end

    # Write our shared deploy secret out to wherever the cloud provider layers
    # like to stash it.
    def writeDeploySecret
      return if !@deploy_secret
      credsets = credsUsed
      return if !credsets
      if !@original_config['scrub_mu_isms'] and !@no_artifacts
        cloudsUsed.each { |cloud|
          credsets.each { |credentials|
            next if MU::Cloud.cloudClass(cloud).credConfig(credentials).nil? # XXX this is a dumb way to check this, should be able to get credsUsed by cloud
            MU::Cloud.cloudClass(cloud).writeDeploySecret(self, @deploy_secret, credentials: credentials)
          }
        }
      end
    end

    private
        
    def writeFile(filename, contents)
      file = File.new("#{deploy_dir}/#{filename}", File::CREAT|File::TRUNC|File::RDWR, 0600)
      file.puts contents
      file.close
    end

    # Helper for +initialize+
    def setDeploySecret
      MU.log "Creating deploy secret for #{MU.deploy_id}"
      @deploy_secret = Password.random(256)
    end

    def loadObjects(delay_descriptor_load)
      # Load up MU::Cloud objects for all our kittens in this deploy

      MU::Cloud.resource_types.each_pair { |res_type, attrs|
        type = attrs[:cfg_plural]
        next if !@deployment.has_key?(type)

        deletia = {}
        @deployment[type].each_pair { |res_name, data|
          orig_cfg = findResourceConfig(type, res_name)

          if orig_cfg.nil?
            MU.log "Failed to locate original config for #{attrs[:cfg_name]} #{res_name} in #{@deploy_id}", MU::WARN if !["firewall_rules", "databases", "storage_pools", "cache_clusters", "alarms"].include?(type) # XXX shaddap
            next
          end

          if orig_cfg['vpc']
            ref = if orig_cfg['vpc']['id'] and orig_cfg['vpc']['id'].is_a?(Hash)
              orig_cfg['vpc']['id']['mommacat'] = self
              MU::Config::Ref.get(orig_cfg['vpc']['id'])
            else
              orig_cfg['vpc']['mommacat'] = self
              MU::Config::Ref.get(orig_cfg['vpc'])
            end
            orig_cfg['vpc'].delete('mommacat')
            orig_cfg['vpc'] = ref if ref.kitten(shallow: true)
          end

          begin
            if attrs[:has_multiples]
              data.keys.each { |mu_name|
                addKitten(type, res_name, attrs[:interface].new(mommacat: self, kitten_cfg: orig_cfg, mu_name: mu_name, delay_descriptor_load: delay_descriptor_load))
              }
            else
              addKitten(type, res_name, attrs[:interface].new(mommacat: self, kitten_cfg: orig_cfg, mu_name: data['mu_name'], cloud_id: data['cloud_id']))
            end
          rescue StandardError => e
            if e.class != MU::Cloud::MuCloudResourceNotImplemented
              MU.log "Failed to load an existing resource of type '#{type}' in #{@deploy_id}: #{e.inspect}", MU::WARN, details: e.backtrace
            end
          end
        }

      }
    end

    # Helper for +initialize+
    def initDeployDirectory
      if !Dir.exist?(MU.dataDir+"/deployments")
        MU.log "Creating #{MU.dataDir}/deployments", MU::DEBUG
        Dir.mkdir(MU.dataDir+"/deployments", 0700)
      end
      path = File.expand_path(MU.dataDir+"/deployments")+"/"+@deploy_id
      if !Dir.exist?(path)
        MU.log "Creating #{path}", MU::DEBUG
        Dir.mkdir(path, 0700)
      end

      @ssh_key_name, @ssh_private_key, @ssh_public_key = self.SSHKey
      if !File.exist?(deploy_dir+"/private_key")
        @private_key, @public_key = createDeployKey
      end

    end

    ###########################################################################
    ###########################################################################
    def loadDeployFromCache(set_context_to_me = true)
      return false if !File.size?(deploy_dir+"/deployment.json")

      lastmod = File.mtime("#{deploy_dir}/deployment.json")
      if @last_modified and lastmod < @last_modified
        MU.log "#{deploy_dir}/deployment.json last written at #{lastmod}, live meta at #{@last_modified}, not loading", MU::WARN if @last_modified
        # this is a weird place for this
        setThreadContextToMe if set_context_to_me
        return true
      end

      deploy = File.open("#{deploy_dir}/deployment.json", File::RDONLY)
      MU.log "Getting lock to read #{deploy_dir}/deployment.json", MU::DEBUG
      # deploy.flock(File::LOCK_EX)
      begin
        Timeout::timeout(90) {deploy.flock(File::LOCK_EX)}
      rescue Timeout::Error
        raise MuError, "Timed out trying to get an exclusive lock on #{deploy_dir}/deployment.json"
      end

      begin
        @deployment = JSON.parse(File.read("#{deploy_dir}/deployment.json"))
# XXX is it worthwhile to merge fuckery?
      rescue JSON::ParserError => e
        MU.log "JSON parse failed on #{deploy_dir}/deployment.json", MU::ERR, details: e.message
      end

      deploy.flock(File::LOCK_UN)
      deploy.close

      setThreadContextToMe if set_context_to_me

      true
    end


    ###########################################################################
    ###########################################################################
    def loadDeploy(deployment_json_only = false, set_context_to_me: true)
      MU::MommaCat.deploy_struct_semaphore.synchronize {
        success = loadDeployFromCache(set_context_to_me)

        @timestamp ||= @deployment['timestamp']
        @seed ||= @deployment['seed']
        @appname ||= @deployment['appname']
        @handle ||= @deployment['handle']

        return if deployment_json_only and success

        if File.exist?(deploy_dir+"/private_key")
          @private_key = File.read("#{deploy_dir}/private_key")
          @public_key = File.read("#{deploy_dir}/public_key")
        end

        if File.exist?(deploy_dir+"/basket_of_kittens.json")
          begin
            @original_config = JSON.parse(File.read("#{deploy_dir}/basket_of_kittens.json"))
          rescue JSON::ParserError => e
            MU.log "JSON parse failed on #{deploy_dir}/basket_of_kittens.json", MU::ERR, details: e.message
          end
        end
        if File.exist?(deploy_dir+"/ssh_key_name")
          @ssh_key_name = File.read("#{deploy_dir}/ssh_key_name").chomp!
        end
        if File.exist?(deploy_dir+"/node_ssh.key")
          @ssh_private_key = File.read("#{deploy_dir}/node_ssh.key")
        end
        if File.exist?(deploy_dir+"/node_ssh.pub")
          @ssh_public_key = File.read("#{deploy_dir}/node_ssh.pub")
        end
        if File.exist?(deploy_dir+"/environment_name")
          @environment = File.read("#{deploy_dir}/environment_name").chomp!
        end
        if File.exist?(deploy_dir+"/deploy_secret")
          @deploy_secret = File.read("#{deploy_dir}/deploy_secret")
        end
        if Dir.exist?("#{deploy_dir}/secrets")
          @secrets.each_key { |type|
            Dir.glob("#{deploy_dir}/secrets/#{type}.*") { |filename|
              server = File.basename(filename).split(/\./)[1]

              @secrets[type][server] = File.read(filename).chomp!
            }
          }
        end
      }
    end

    def findResourceConfig(type, name, config = @original_config)
      orig_cfg = nil
      if config.has_key?(type)
        config[type].each { |resource|
          if resource["name"] == name
            orig_cfg = resource
            break
          end
        }
      end
  
      # Some Server objects originated from ServerPools, get their
      # configs from there
      if type == "servers" and orig_cfg.nil? and config.has_key?("server_pools")
        config["server_pools"].each { |resource|
          if resource["name"] == name
            orig_cfg = resource
            break
          end
        }
      end

      orig_cfg
    end

  end #class
end #module
