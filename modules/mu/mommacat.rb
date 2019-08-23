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

autoload :Net, 'net/ssh'
require 'fileutils'
require 'json'
require 'stringio'
require 'securerandom'
require 'timeout'

module MU

  # MommaCat is in charge of managing metadata about resources we've created,
  # as well as orchestrating amongst them and bootstrapping nodes outside of
  # the normal synchronous deploy sequence invoked by *mu-deploy*.
  class MommaCat

    # An exception denoting a failure in MommaCat#fetchSecret and related methods
    class SecretError < MuError;
    end

    # Failure to load or create a deploy
    class DeployInitializeError < MuError;
    end

    # Failure to groom a node
    class GroomError < MuError;
    end

    @@litters = {}
    @@litter_semaphore = Mutex.new

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
      @@litter_semaphore.synchronize {

        if !use_cache or !@@litters.has_key?(deploy_id) or @@litters[deploy_id].kittens.nil? or @@litters[deploy_id].kittens.size == 0
          @@litters[deploy_id] = MU::MommaCat.new(deploy_id, set_context_to_me: set_context_to_me)
        elsif set_context_to_me
          MU::MommaCat.setThreadContext(@@litters[deploy_id])
        end
        return @@litters[deploy_id]
      }
#     MU::MommaCat.new(deploy_id, set_context_to_me: set_context_to_me)
    end

    attr_reader :public_key
    attr_reader :deploy_secret
    attr_reader :deployment
    attr_reader :original_config
    attr_reader :environment
    attr_reader :ssh_key_name
    attr_reader :ssh_public_key
    attr_reader :nocleanup
    attr_reader :deploy_id
    attr_reader :timestamp
    attr_reader :appname
    attr_reader :handle
    attr_reader :seed
    attr_reader :mu_user
    attr_reader :clouds
    attr_reader :chef_user
    attr_reader :no_artifacts
    attr_accessor :kittens # really want a method only available to :Deploy
    @myhome = Etc.getpwuid(Process.uid).dir
    @nagios_home = "/opt/mu/var/nagios_user_home"
    @locks = Hash.new
    @deploy_cache = Hash.new
    @nocleanup = false
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

    @@deploy_struct_semaphore = Mutex.new
    # Don't let things that modify the deploy struct Hash step on each other.
    # @return [Mutex]
    def self.deploy_struct_semaphore;
      @@deploy_struct_semaphore
    end

    # Set the current threads' context (some knucklehead global variables) to
    # values pertinent to the given deployment object.
    # @param deploy [MU::MommaCat]: A deployment object
    def self.setThreadContext(deploy)
      raise MuError, "Didn't get a MU::MommaCat object in setThreadContext" if !deploy.is_a?(MU::MommaCat)
      if !deploy.mu_user.nil?
        MU.setVar("chef_user", deploy.chef_user)
        if deploy.mu_user != "mu" and deploy.mu_user != "root"
          MU.setVar("dataDir", Etc.getpwnam(deploy.mu_user).dir+"/.mu/var")
          MU.setVar("mu_user", deploy.mu_user)
        else
          MU.setVar("dataDir", MU.mainDataDir)
          MU.setVar("mu_user", "root")
        end
      end
      MU.setVar("mommacat", deploy)
      MU.setVar("deploy_id", deploy.deploy_id)
      MU.setVar("appname", deploy.appname)
      MU.setVar("environment", deploy.environment)
      MU.setVar("timestamp", deploy.timestamp)
      MU.setVar("seed", deploy.seed)
      MU.setVar("handle", deploy.handle)
    end

    # @param deploy_id [String]: The MU identifier of the deployment to load or create.
    # @param create [Boolean]: Create a new deployment instead of searching for an existing one.
    # @param deploy_secret [String]: A secret encrypted by the private key of a deployment we're loading. Used to validate remote requests to bootstrap into this deployment.
    # @param config [Hash]: The full configuration, parsed by {MU::Config}, of this deployment. Required when creating a new deployment.
    # @param environment [String]: The environment of a deployment to create.
    # @param ssh_key_name [String]: Required when creating a new deployment.
    # @param ssh_private_key [String]: Required when creating a new deployment.
    # @param ssh_public_key [String]: SSH public key for authorized_hosts on clients.
    # @param skip_resource_objects [Boolean]: Whether preload the cloud resource objects from this deploy. Can save load time for simple MommaCat tasks.
    # @param nocleanup [Boolean]: Skip automatic cleanup of failed resources
    # @param no_artifacts [Boolean]: Do not save deploy metadata
    # @param deployment_data [Hash]: Known deployment data.
    # @return [void]
    def initialize(deploy_id,
                   create: false,
                   deploy_secret: nil,
                   config: nil,
                   environment: "dev",
                   ssh_key_name: nil,
                   ssh_private_key: nil,
                   ssh_public_key: nil,
                   nocleanup: false,
                   set_context_to_me: true,
                   skip_resource_objects: false,
                   no_artifacts: false,
                   deployment_data: {},
                   mu_user: Etc.getpwuid(Process.uid).name
    )
      if deploy_id.nil? or deploy_id.empty?
        raise DeployInitializeError, "MommaCat objects must specify a deploy_id"
      end
      set_context_to_me = true if create

      @deploy_id = deploy_id
      @mu_user = mu_user.dup
      @no_artifacts = no_artifacts

      # Make sure mu_user and chef_user are sane.
      if @mu_user == "root"
        @chef_user = "mu"
      else
        @chef_user = @mu_user.dup.gsub(/\./, "")
        @mu_user = "root" if @mu_user == "mu"
      end
      @kitten_semaphore = Mutex.new
      @kittens = {}
      @original_config = config
      @nocleanup = nocleanup
      @secret_semaphore = Mutex.new
      @notify_semaphore = Mutex.new
      @node_cert_semaphore = Mutex.new
      @deployment = deployment_data
      @deployment['mu_public_ip'] = MU.mu_public_ip
      @private_key = nil
      @public_key = nil
      @secrets = Hash.new
      @secrets['instance_secret'] = Hash.new
      @environment = environment
      @ssh_key_name = ssh_key_name
      @ssh_private_key = ssh_private_key
      @ssh_public_key = ssh_public_key
      @clouds = {}
      @seed = MU.seed # pass this in
      @handle = MU.handle # pass this in
      if set_context_to_me
        MU::MommaCat.setThreadContext(self)
      end
      if create and !@no_artifacts
        if !Dir.exist?(MU.dataDir+"/deployments")
          MU.log "Creating #{MU.dataDir}/deployments", MU::DEBUG
          Dir.mkdir(MU.dataDir+"/deployments", 0700)
        end
        path = File.expand_path(MU.dataDir+"/deployments")+"/"+@deploy_id
        if !Dir.exist?(path)
          MU.log "Creating #{path}", MU::DEBUG
          Dir.mkdir(path, 0700)
        end
        if @original_config.nil? or !@original_config.is_a?(Hash)
          raise DeployInitializeError, "New MommaCat repository requires config hash"
        end
        credsets = {}
        @appname = @original_config['name']
        MU::Cloud.resource_types.each { |cloudclass, data|
          if !@original_config[data[:cfg_plural]].nil? and @original_config[data[:cfg_plural]].size > 0
            @original_config[data[:cfg_plural]].each { |resource|
              credsets[resource['cloud']] ||= []
              credsets[resource['cloud']] << resource['credentials']
              @clouds[resource['cloud']] = 0 if !@clouds.has_key?(resource['cloud'])
              @clouds[resource['cloud']] = @clouds[resource['cloud']] + 1
            }
          end
        }
        @ssh_key_name, @ssh_private_key, @ssh_public_key = self.SSHKey
        if !File.exist?(deploy_dir+"/private_key")
          @private_key, @public_key = createDeployKey
        end
        MU.log "Creating deploy secret for #{MU.deploy_id}"
        @deploy_secret = Password.random(256)
        if !@original_config['scrub_mu_isms']
          credsets.each_pair { |cloud, creds|
            creds.uniq!
            cloudclass = Object.const_get("MU").const_get("Cloud").const_get(cloud)
            creds.each { |credentials|
              cloudclass.writeDeploySecret(@deploy_id, @deploy_secret, credentials: credentials)
            }
          }
        end
        if set_context_to_me
          MU::MommaCat.setThreadContext(self)
        end
        save!
      end


      loadDeploy(set_context_to_me: set_context_to_me)
      if !deploy_secret.nil?
        if !authKey(deploy_secret)
          raise DeployInitializeError, "Invalid or incorrect deploy key."
        end
      end


      # Initialize a MU::Cloud object for each resource belonging to this
      # deploy, IF it already exists, which is to say if we're loading an
      # existing deploy instead of creating a new one.
      if !create and @deployment and @original_config and !skip_resource_objects
        MU::Cloud.resource_types.each_pair { |res_type, attrs|
          type = attrs[:cfg_plural]
          if @deployment.has_key?(type)
            @deployment[type].each_pair { |res_name, data|
              orig_cfg = nil
              if @original_config.has_key?(type)
                @original_config[type].each { |resource|
                  if resource["name"] == res_name
                    orig_cfg = resource
                    break
                  end
                }
              end

              # Some Server objects originated from ServerPools, get their
              # configs from there
              if type == "servers" and orig_cfg.nil? and
                  @original_config.has_key?("server_pools")
                @original_config["server_pools"].each { |resource|
                  if resource["name"] == res_name
                    orig_cfg = resource
                    break
                  end
                }
              end
              if orig_cfg.nil?
                MU.log "Failed to locate original config for #{attrs[:cfg_name]} #{res_name} in #{@deploy_id}", MU::WARN if !["firewall_rules", "databases", "storage_pools", "cache_clusters", "alarms"].include?(type) # XXX shaddap
                next
              end
              begin
                # Load up MU::Cloud objects for all our kittens in this deploy
                orig_cfg['environment'] = @environment # not always set in old deploys
                if attrs[:has_multiples]
                  data.each_pair { |mu_name, actual_data|
                    attrs[:interface].new(mommacat: self, kitten_cfg: orig_cfg, mu_name: mu_name)
                  }
                else
                  # XXX hack for old deployments, this can go away some day
                  if data['mu_name'].nil? or data['mu_name'].empty?
                    if res_type.to_s == "LoadBalancer" and !data['awsname'].nil?
                      data['mu_name'] = data['awsname'].dup
                    elsif res_type.to_s == "FirewallRule" and !data['group_name'].nil?
                      data['mu_name'] = data['group_name'].dup
                    elsif res_type.to_s == "Database" and !data['identifier'].nil?
                      data['mu_name'] = data['identifier'].dup.upcase
                    elsif res_type.to_s == "VPC"
                      # VPC names are deterministic, just generate the things
                      data['mu_name'] = getResourceName(data['name'])
                    end
                  end
                  if data['mu_name'].nil?
                    raise MuError, "Unable to find or guess a Mu name for #{res_type}: #{res_name} in #{@deploy_id}"
                  end
                  attrs[:interface].new(mommacat: self, kitten_cfg: orig_cfg, mu_name: data['mu_name'], cloud_id: data['cloud_id'])
                end
              rescue Exception => e
                if e.class != MU::Cloud::MuCloudResourceNotImplemented
                  MU.log "Failed to load an existing resource of type '#{type}' in #{@deploy_id}: #{e.inspect}", MU::WARN, details: e.backtrace
                end
              end
            }
          end
        }
      end

# XXX this .owned? method may get changed by the Ruby maintainers
#     if !@@litter_semaphore.owned?
#       @@litter_semaphore.synchronize {
#         @@litters[@deploy_id] = self
#       }
#     end
    end

    # Tell us the number of first-class resources we've configured, optionally
    # filtering results to only include a given type and/or in a given cloud
    # environment.
    # @param clouds [Array<String>]: The cloud environment(s) to check for. If unspecified, will match all environments in this deployment.
    # @param types [Array<String>]: The type of resource(s) to check for. If unspecified, will match all resources in this deployment.
    # @param negate [Boolean]: Invert logic of the other filters if they are specified, e.g. search for all cloud resources that are *not* AWS.
    def numKittens(clouds: [], types: [], negate: false)
      realtypes = []
      return 0 if @original_config.nil?
      if !types.nil? and types.size > 0
        types.each { |type|
          shortclass, cfg_name, cfg_plural, classname = MU::Cloud.getResourceNames(type)
          realtypes << cfg_plural
        }
      end

      count = 0
      MU::Cloud.resource_types.each { |cloudclass, data|
        next if @original_config[data[:cfg_plural]].nil?
        next if realtypes.size > 0 and (!negate and !realtypes.include?(data[:cfg_plural]))
        @original_config[data[:cfg_plural]].each { |resource|
          if clouds.nil? or clouds.size == 0 or (!negate and clouds.include?(resource["cloud"])) or (negate and !clouds.include?(resource["cloud"]))
            count = count + 1
          end
        }
      }
      count
    end

    # @param object [MU::Cloud]:
    def removeKitten(object)
      if !object
        raise MuError, "Nil arguments to removeKitten are not allowed"
      end
      @kitten_semaphore.synchronize {
        MU::Cloud.resource_types.each_pair { |name, attrs|
          type = attrs[:cfg_plural]
          next if !@kittens.has_key?(type)
          tmplitter = @kittens[type].values.dup
          tmplitter.each { |nodeclass, data|
            if data.is_a?(Hash)
              data.each_pair { |mu_name, obj|
                if data == object
                  @kittens[type][nodeclass].delete(mu_name)
                  return
                end
              }
            else
              if data == object
                @kittens[type].delete(nodeclass)
                return
              end
            end
          }
        }
      }
      @kittens
    end

    # Overwrite this deployment's configuration with a new version. Save the
    # previous version as well.
    # @param new_conf [Hash]: A new configuration, fully resolved by {MU::Config}
    def updateBasketofKittens(new_conf)
      loadDeploy
      if new_conf == @original_config
        MU.log "#{@deploy_id}", MU::WARN
        return
      end

      backup = "#{deploy_dir}/basket_of_kittens.json.#{Time.now.to_i.to_s}"
      MU.log "Saving previous config of #{@deploy_id} to #{backup}"
      config = File.new(backup, File::CREAT|File::TRUNC|File::RDWR, 0600)
      config.flock(File::LOCK_EX)
      config.puts JSON.pretty_generate(@original_config)
      config.flock(File::LOCK_UN)
      config.close

      @original_config = new_conf
#      save! # XXX this will happen later, more sensibly
      MU.log "New config saved to #{deploy_dir}/basket_of_kittens.json"
    end

    # Keep tabs on a {MU::Cloud} object so that it can be found easily by
    # #findLitterMate.
    # @param type [String]:
    # @param name [String]:
    # @param object [MU::Cloud]:
    def addKitten(type, name, object)
      if !type or !name or !object or !object.mu_name
        raise MuError, "Nil arguments to addKitten are not allowed (got type: #{type}, name: #{name}, and '#{object}' to add)"
      end
      shortclass, cfg_name, cfg_plural, classname, attrs = MU::Cloud.getResourceNames(type)
      type = cfg_plural
      has_multiples = attrs[:has_multiples]

      @kitten_semaphore.synchronize {
        @kittens[type] ||= {}
        if has_multiples
          @kittens[type][name] ||= {}
          @kittens[type][name][object.mu_name] = object
        else
          @kittens[type][name] = object
        end
      }
    end

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
        if my_key.private_decrypt(ciphertext).force_encoding("UTF-8") == @deploy_secret.force_encoding("UTF-8")
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

    # Generate a three-character string which can be used to unique-ify the
    # names of resources which might potentially collide, e.g. Windows local
    # hostnames, Amazon Elastic Load Balancers, or server pool instances.
    # @return [String]: A three-character string consisting of two alphnumeric
    # characters (uppercase) and one number.
    def self.genUniquenessString
      begin
        candidate = SecureRandom.base64(2).slice(0..1) + SecureRandom.random_number(9).to_s
        candidate.upcase!
      end while candidate.match(/[^A-Z0-9]/)
      return candidate
    end

    @unique_map_semaphore = Mutex.new
    @name_unique_str_map = {}
    # Keep a map of the uniqueness strings we assign to various full names, in
    # case we want to reuse them later.
    # @return [Hash<String>]
    def self.name_unique_str_map
      @name_unique_str_map
    end

    # Keep a map of the uniqueness strings we assign to various full names, in
    # case we want to reuse them later.
    # @return [Mutex]
    def self.unique_map_semaphore
      @unique_map_semaphore
    end

    # Generate a name string for a resource, incorporate the MU identifier
    # for this deployment. Will dynamically shorten the name to fit for
    # restrictive uses (e.g. Windows local hostnames, Amazon Elastic Load
    # Balancers).
    # @param name [String]: The shorthand name of the resource, usually the value of the "name" field in an Mu resource declaration.
    # @param max_length [Integer]: The maximum length of the resulting resource name.
    # @param need_unique_string [Boolean]: Whether to forcibly append a random three-character string to the name to ensure it's unique. Note that this behavior will be automatically invoked if the name must be truncated.
    # @param scrub_mu_isms [Boolean]: Don't bother with generating names specific to this deployment. Used to generate generic CloudFormation templates, amongst other purposes.
    # @return [String]: A full name string for this resource
    def getResourceName(name, max_length: 255, need_unique_string: false, use_unique_string: nil, reuse_unique_string: false, scrub_mu_isms: @original_config['scrub_mu_isms'])
      if name.nil?
        raise MuError, "Got no argument to MU::MommaCat.getResourceName"
      end
      if @appname.nil? or @environment.nil? or @timestamp.nil? or @seed.nil?
        MU.log "Missing global deploy variables in thread #{Thread.current.object_id}, using bare name '#{name}' (appname: #{@appname}, environment: #{@environment}, timestamp: #{@timestamp}, seed: #{@seed}", MU::WARN, details: caller
        return name
      end
      need_unique_string = false if scrub_mu_isms

      muname = nil
      if need_unique_string
        reserved = 4
      else
        reserved = 0
      end

      # First, pare down the base name string until it will fit
      basename = @appname.upcase + "-" + @environment.upcase + "-" + @timestamp + "-" + @seed.upcase + "-" + name.upcase
      if scrub_mu_isms
        basename = @appname.upcase + "-" + @environment.upcase + name.upcase
      end

      begin
        if (basename.length + reserved) > max_length
          MU.log "Stripping name down from #{basename}[#{basename.length.to_s}] (reserved: #{reserved.to_s}, max_length: #{max_length.to_s})", MU::DEBUG
          if basename == @appname.upcase + "-" + @seed.upcase + "-" + name.upcase
            # If we've run out of stuff to strip, truncate what's left and
            # just leave room for the deploy seed and uniqueness string. This
            # is the bare minimum, and probably what you'll see for most Windows
            # hostnames.
            basename = name.upcase + "-" + @appname.upcase
            basename.slice!((max_length-(reserved+3))..basename.length)
            basename.sub!(/-$/, "")
            basename = basename + "-" + @seed.upcase
          else
            # If we have to strip anything, assume we've lost uniqueness and
            # will have to compensate with #genUniquenessString.
            need_unique_string = true
            reserved = 4
            basename.sub!(/-[^-]+-#{@seed.upcase}-#{Regexp.escape(name.upcase)}$/, "")
            basename = basename + "-" + @seed.upcase + "-" + name.upcase
          end
        end
      end while (basename.length + reserved) > max_length

      # Finally, apply our short random differentiator, if it's needed.
      if need_unique_string
        # Preferentially use a requested one, if it's not already in use.
        if !use_unique_string.nil?
          muname = basename + "-" + use_unique_string
          if !allocateUniqueResourceName(muname) and !reuse_unique_string
            MU.log "Requested to use #{use_unique_string} as differentiator when naming #{name}, but the name #{muname} is unavailable.", MU::WARN
            muname = nil
          end
        end
        if !muname
          begin
            unique_string = MU::MommaCat.genUniquenessString
            muname = basename + "-" + unique_string
          end while !allocateUniqueResourceName(muname)
          MU::MommaCat.unique_map_semaphore.synchronize {
            MU::MommaCat.name_unique_str_map[muname] = unique_string
          }
        end
      else
        muname = basename
      end

      return muname
    end


    # Encrypt a string with the deployment's public key.
    # @param ciphertext [String]: The string to encrypt
    def encryptWithDeployKey(ciphertext)
      my_public_key = OpenSSL::PKey::RSA.new(@public_key)
      return my_public_key.public_encrypt(ciphertext)
    end

    # Decrypt a string with the deployment's private key.
    # @param ciphertext [String]: The string to decrypt
    def decryptWithDeployKey(ciphertext)
      my_private_key = OpenSSL::PKey::RSA.new(@private_key)
      return my_private_key.private_decrypt(ciphertext)
    end


    # Save a string into deployment metadata for the current deployment,
    # encrypting it with our deploy key.
    # @param instance_id [String]: The cloud instance identifier with which this secret is associated.
    # @param raw_secret [String]: The unencrypted string to store.
    # @param type [String]: The type of secret, used to identify for retrieval.
    def saveNodeSecret(instance_id, raw_secret, type)
      return if @no_artifacts
      if instance_id.nil? or instance_id.empty? or raw_secret.nil? or raw_secret.empty? or type.nil? or type.empty?
        raise SecretError, "saveNodeSecret requires instance_id, raw_secret, and type args"
      end
      MU::MommaCat.lock("deployment-notification")
      loadDeploy(true) # make sure we're not trampling deployment data
      @secret_semaphore.synchronize {
        if @secrets[type].nil?
          raise SecretError, "'#{type}' is not a valid secret type (valid types: #{@secrets.keys.to_s})"
        end
        @secrets[type][instance_id] = encryptWithDeployKey(raw_secret)
      }
      save!
      MU::MommaCat.unlock("deployment-notification")
    end

    # Retrieve an encrypted secret from metadata for the current deployment.
    # @param instance_id [String]: The cloud instance identifier with which this secret is associated.
    # @param type [String]: The type of secret, used to identify for retrieval.
    # @param quiet [Boolean]: Do not log errors for non-existent secrets
    def fetchSecret(instance_id, type, quiet: false)
      @secret_semaphore.synchronize {
        if @secrets[type].nil?
          return nil if quiet
          raise SecretError, "'#{type}' is not a valid secret type (valid types: #{@secrets.keys.to_s})"
        end
        if @secrets[type][instance_id].nil?
          return nil if quiet
          raise SecretError, "No '#{type}' secret known for instance #{instance_id}"
        end
      }
      return decryptWithDeployKey(@secrets[type][instance_id])
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
      rescue Exception => e
        MU::MommaCat.unlockAll
        if e.class.name != "MU::Cloud::AWS::Server::BootstrapTempFail" and !File.exists?(deploy_dir+"/.cleanup."+cloud_id) and !File.exists?(deploy_dir+"/.cleanup")
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

      if !@deployment['servers'].nil?
        syncLitter(@deployment["servers"].keys, triggering_node: kitten)
      end
      MU::MommaCat.unlock(cloud_id+"-mommagroom")
      if MU.myCloud == "AWS"
        MU::Cloud::AWS.openFirewallForClients # XXX add the other clouds, or abstract
      end
      MU::MommaCat.getLitter(MU.deploy_id, use_cache: false)
      MU::MommaCat.syncMonitoringConfig(false)
      MU.log "Grooming complete for '#{name}' mu_name on \"#{MU.handle}\" (#{MU.deploy_id})"
      FileUtils.touch(MU.dataDir+"/deployments/#{MU.deploy_id}/#{name}_done.txt")
      MU::MommaCat.unlockAll
      if first_groom
        sendAdminSlack("Grooming complete for #{mu_name} :heart_eyes_cat:")
        sendAdminMail("Grooming complete for '#{name}' (#{mu_name}) on deploy \"#{MU.handle}\" (#{MU.deploy_id})")
      end
      return
    end

    # Return the parts and pieces of this deploy's node ssh key set. Generate
    # or load if that hasn't been done already.
    def SSHKey
      return [@ssh_key_name, @ssh_private_key, @ssh_public_key] if !@ssh_key_name.nil?
      if numKittens(types: ["Server", "ServerPool", "ContainerCluster"]) == 0
        return []
      end
      @ssh_key_name="deploy-#{MU.deploy_id}"
      ssh_dir = Etc.getpwnam(@mu_user).dir+"/.ssh"

      if !File.directory?(ssh_dir) then
        MU.log "Creating #{ssh_dir}", MU::DEBUG
        Dir.mkdir(ssh_dir, 0700)
        if Process.uid == 0 and @mu_user != "mu"
          ssh_dir.chown(Etc.getpwnam(@mu_user).uid, Etc.getpwnam(@mu_user).gid)
        end
      end
      if !File.exists?("#{ssh_dir}/#{@ssh_key_name}")
        MU.log "Generating SSH key #{@ssh_key_name}"
        %x{/usr/bin/ssh-keygen -N "" -f #{ssh_dir}/#{@ssh_key_name}}
      end
      @ssh_public_key = File.read("#{ssh_dir}/#{@ssh_key_name}.pub")
      @ssh_public_key.chomp!
      @ssh_private_key = File.read("#{ssh_dir}/#{@ssh_key_name}")
      @ssh_private_key.chomp!

      if numKittens(clouds: ["AWS"], types: ["Server", "ServerPool", "ContainerCluster"]) > 0
        creds_used = []
        ["servers", "server_pools", "container_clusters"].each { |type|
          next if @original_config[type].nil?
          @original_config[type].each { |descriptor|
            if descriptor['credentials']
              creds_used << descriptor['credentials']
            else
              creds_used << MU::Cloud::AWS.credConfig(name_only: true)
            end
          }
        }
        creds_used << nil if creds_used.empty?

        creds_used.uniq.each { |credset|
          MU::Cloud::AWS.createEc2SSHKey(@ssh_key_name, @ssh_public_key, credentials: credset)
        }
      end

      return [@ssh_key_name, @ssh_private_key, @ssh_public_key]
    end

    @lock_semaphore = Mutex.new
    # Release all flock() locks held by the current thread.
    def self.unlockAll
      if !@locks.nil? and !@locks[Thread.current.object_id].nil?
        # Work from a copy so we can iterate without worrying about contention
        # in lock() or unlock(). We can't just wrap our iterator block in a
        # semaphore here, because we're calling another method that uses the
        # same semaphore.
        lock_copy = nil
        @lock_semaphore.synchronize {
          delete_list = []
          @locks[Thread.current.object_id].each_pair { |id, fh|
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
    def self.lock(id, nonblock = false, global = false)
      raise MuError, "Can't pass a nil id to MU::MommaCat.lock" if id.nil?

      if !global
        lockdir = "#{deploy_dir(MU.deploy_id)}/locks"
      else
        lockdir = File.expand_path(MU.dataDir+"/locks")
      end

      if !Dir.exist?(lockdir)
        MU.log "Creating #{lockdir}", MU::DEBUG
        Dir.mkdir(lockdir, 0700)
      end

      @lock_semaphore.synchronize {
        if @locks[Thread.current.object_id].nil?
          @locks[Thread.current.object_id] = Hash.new
        end

        @locks[Thread.current.object_id][id] = File.open("#{lockdir}/#{id}.lock", File::CREAT|File::RDWR, 0600)
      }
      MU.log "Getting a lock on #{lockdir}/#{id}.lock (thread #{Thread.current.object_id})...", MU::DEBUG
      begin
        if nonblock
          if !@locks[Thread.current.object_id][id].flock(File::LOCK_EX|File::LOCK_NB)
            return false
          end
        else
          @locks[Thread.current.object_id][id].flock(File::LOCK_EX)
        end
      rescue IOError => e
        raise MU::BootstrapTempFail, "Interrupted waiting for lock on thread #{Thread.current.object_id}, probably just a node rebooting as part of a synchronous install"
      end
      MU.log "Lock on #{lockdir}/#{id}.lock on thread #{Thread.current.object_id} acquired", MU::DEBUG
      return true
    end

    # Release a flock() lock.
    # @param id [String]: The lock identifier to release.
    def self.unlock(id, global = false)
      raise MuError, "Can't pass a nil id to MU::MommaCat.unlock" if id.nil?
      lockdir = nil
      if !global
        lockdir = "#{deploy_dir(MU.deploy_id)}/locks"
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
        MU.log "Purging #{path}/#{deploy_id}" if File.exists?(path+"/"+deploy_id+"/deployment.json")

        FileUtils.rm_rf(path+"/"+deploy_id, :secure => true)
      end
      if File.exists?(path+"/unique_ids")
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

    @cleanup_threads = []

    # Iterate over all known deployments and look for instances that have been
    # terminated, but not yet cleaned up, then clean them up.
    def self.cleanTerminatedInstances
      MU::MommaCat.lock("clean-terminated-instances", false, true)
      MU.log "Checking for harvested instances in need of cleanup", MU::DEBUG
      parent_thread_id = Thread.current.object_id
      cleanup_threads = []
      purged = 0
      MU::MommaCat.listDeploys.each { |deploy_id|
        next if File.exists?(deploy_dir(deploy_id)+"/.cleanup")
        MU.log "Checking for dead wood in #{deploy_id}", MU::DEBUG
        @cleanup_threads << Thread.new {
          MU.dupGlobals(parent_thread_id)
          # We can't use cached litter information because we will then try to delete the same node over and over again until we restart the service
          deploy = MU::MommaCat.getLitter(deploy_id, set_context_to_me: true, use_cache: false)
          purged_this_deploy = 0
          if deploy.kittens.has_key?("servers")
            deploy.kittens["servers"].each_pair { |nodeclass, servers|
              deletia = []
              servers.each_pair { |mu_name, server|
                server.describe
                if !server.cloud_id
                  MU.log "Checking for presence of #{mu_name}, but unable to fetch its cloud_id", MU::WARN, details: server
                elsif !server.active?
                  next if File.exists?(deploy_dir(deploy_id)+"/.cleanup-"+server.cloud_id)
                  deletia << mu_name
                  MU.log "Cleaning up metadata for #{server} (#{nodeclass}), formerly #{server.cloud_id}, which appears to have been terminated", MU::NOTICE
                  begin
                    server.destroy
                    deploy.sendAdminMail("Retired metadata for terminated node #{mu_name}")
                    deploy.sendAdminSlack("Retired metadata for terminated node `#{mu_name}`")
                  rescue Exception => e
                    MU.log "Saw #{e.message} while retiring #{mu_name}", MU::ERR, details: e.backtrace
                    next
                  end
                  MU.log "Cleanup of metadata for #{server} (#{nodeclass}), formerly #{server.cloud_id} complete", MU::NOTICE
                  purged = purged + 1
                  purged_this_deploy = purged_this_deploy + 1
                end
              }
              if purged_this_deploy > 0
                # XXX some kind of filter (obey sync_siblings on nodes' configs)
                deploy.syncLitter(servers.keys)
              end
            }
          end
          MU.purgeGlobals
        }
      }
      @cleanup_threads.each { |t|
        t.join
      }
      @cleanup_threads = []

      if purged > 0
        if MU.myCloud == "AWS"
          MU::Cloud::AWS.openFirewallForClients # XXX add the other clouds, or abstract
        end
        MU::MommaCat.syncMonitoringConfig
      end
      MU::MommaCat.unlock("clean-terminated-instances", true)
    end


    # Locate a resource that's either a member of another deployment, or of no
    # deployment at all, and return a {MU::Cloud} object for it.
    # @param cloud [String]: The Cloud provider to use.
    # @param type [String]: The resource type. Can be the full class name, symbolic name, or Basket of Kittens configuration shorthand for the resource type.
    # @param deploy_id [String]: The identifier of an outside deploy to search.
    # @param name [String]: The name of the resource as defined in its 'name' Basket of Kittens field, typically used in conjunction with deploy_id.
    # @param mu_name [String]: The fully-resolved and deployed name of the resource, typically used in conjunction with deploy_id.
    # @param cloud_id [String]: A cloud provider identifier for this resource.
    # @param region [String]: The cloud provider region
    # @param tag_key [String]: A cloud provider tag to help identify the resource, used in conjunction with tag_value.
    # @param tag_value [String]: A cloud provider tag to help identify the resource, used in conjunction with tag_key.
    # @param allow_multi [Boolean]: Permit an array of matching resources to be returned (if applicable) instead of just one.
    # @param dummy_ok [Boolean]: Permit return of a faked {MU::Cloud} object if we don't have enough information to identify a real live one.
    # @param flags [Hash]: Other cloud or resource type specific options to pass to that resource's find() method
    # @return [Array<MU::Cloud>]
    def self.findStray(cloud,
        type,
        deploy_id: nil,
        name: nil,
        mu_name: nil,
        cloud_id: nil,
        credentials: nil,
        region: nil,
        tag_key: nil,
        tag_value: nil,
        allow_multi: false,
        calling_deploy: MU.mommacat,
        flags: {},
        dummy_ok: false,
        debug: false
    )
      return nil if cloud == "CloudFormation" and !cloud_id.nil?
      begin
        deploy_id = deploy_id.to_s if deploy_id.class.to_s == "MU::Config::Tail"
        name = name.to_s if name.class.to_s == "MU::Config::Tail"
        cloud_id = cloud_id.to_s if !cloud_id.nil?
        mu_name = mu_name.to_s if mu_name.class.to_s == "MU::Config::Tail"
        tag_key = tag_key.to_s if tag_key.class.to_s == "MU::Config::Tail"
        tag_value = tag_value.to_s if tag_value.class.to_s == "MU::Config::Tail"
        shortclass, cfg_name, cfg_plural, classname, attrs = MU::Cloud.getResourceNames(type)
        resourceclass = MU::Cloud.loadCloudType(cloud, shortclass)
        cloudclass = Object.const_get("MU").const_get("Cloud").const_get(cloud)

        credlist = if credentials
          [credentials]
        else
          cloudclass.listCredentials
        end

        if (tag_key and !tag_value) or (!tag_key and tag_value)
          raise MuError, "Can't call findStray with only one of tag_key and tag_value set, must be both or neither"
        end
        # Help ourselves by making more refined parameters out of mu_name, if
        # they weren't passed explicitly
        if mu_name
          if !tag_key and !tag_value
            # XXX "Name" is an AWS-ism, perhaps those plugins should do this bit?
            tag_key="Name"
            tag_value=mu_name
          end
          # We can extract a deploy_id from mu_name if we don't have one already
          if !deploy_id and mu_name
            deploy_id = mu_name.sub(/^(\w+-\w+-\d{10}-[A-Z]{2})-/, '\1')
          end
        end
        loglevel = debug ? MU::NOTICE : MU::DEBUG

        MU.log "findStray(cloud: #{cloud}, type: #{type}, deploy_id: #{deploy_id}, calling_deploy: #{calling_deploy.deploy_id if !calling_deploy.nil?}, name: #{name}, cloud_id: #{cloud_id}, tag_key: #{tag_key}, tag_value: #{tag_value}, credentials: #{credentials})", loglevel, details: flags

        # See if the thing we're looking for is a member of the deploy that's
        # asking after it.
        if !deploy_id.nil? and !calling_deploy.nil? and flags.empty? and
            calling_deploy.deploy_id == deploy_id and (!name.nil? or !mu_name.nil?)
          handle = calling_deploy.findLitterMate(type: type, name: name, mu_name: mu_name, cloud_id: cloud_id, credentials: credentials)
          return [handle] if !handle.nil?
        end

        kittens = {}
        # Search our other deploys for matching resources
        if (deploy_id or name or mu_name or cloud_id)# and flags.empty?
          mu_descs = MU::MommaCat.getResourceMetadata(cfg_plural, name: name, deploy_id: deploy_id, mu_name: mu_name)

          mu_descs.each_pair { |deploy_id, matches|
            MU.log "findStray: #{deploy_id} had #{matches.size.to_s} initial matches", loglevel
            next if matches.nil? or matches.size == 0
            momma = MU::MommaCat.getLitter(deploy_id)
            straykitten = nil


            # If we found exactly one match in this deploy, use its metadata to
            # guess at resource names we weren't told.
            if matches.size == 1 and name.nil? and mu_name.nil?
              if cloud_id.nil?
                straykitten = momma.findLitterMate(type: type, name: matches.first["name"], cloud_id: matches.first["cloud_id"], credentials: credentials)
              else
                MU.log "findStray: attempting to narrow down with cloud_id #{cloud_id}", loglevel
                straykitten = momma.findLitterMate(type: type, name: matches.first["name"], cloud_id: cloud_id, credentials: credentials)
              end
#            elsif !flags.nil? and !flags.empty? # XXX eh, maybe later
#              # see if we can narrow it down further with some flags
#              filtered = []
#              matches.each { |m|
#                f = resourceclass.find(cloud_id: m['mu_name'], flags: flags)
#                filtered << m if !f.nil? and f.size > 0
#                MU.log "RESULT FROM find(cloud_id: #{m['mu_name']}, flags: #{flags})", MU::WARN, details: f
#              }
#              if filtered.size == 1
#                straykitten = momma.findLitterMate(type: type, name: matches.first["name"], cloud_id: filtered.first['cloud_id'])
#              end
            else
              # There's more than one of this type of resource in the target
              # deploy, so see if findLitterMate can narrow it down for us
              straykitten = momma.findLitterMate(type: type, name: name, mu_name: mu_name, cloud_id: cloud_id, credentials: credentials)
            end

            next if straykitten.nil?

            if straykitten.cloud_id.nil?
              MU.log "findStray: kitten #{straykitten.mu_name} came back with nil cloud_id", MU::WARN
              next
            end

            kittens[straykitten.cloud_id] = straykitten

            # Peace out if we found the exact resource we want
            if cloud_id and straykitten.cloud_id == cloud_id
              return [straykitten]
            # ...or if we've validated our one possible match
            elsif !cloud_id and mu_descs.size == 1 and matches.size == 1
              return [straykitten]
            elsif credentials and credlist.size == 1 and straykitten.credentials == credentials
              return [straykitten]
            end
          }


#          if !mu_descs.nil? and mu_descs.size > 0 and !deploy_id.nil? and !deploy_id.empty? and !mu_descs.first.empty?
#             MU.log "I found descriptions that might match #{resourceclass.cfg_plural} name: #{name}, deploy_id: #{deploy_id}, mu_name: #{mu_name}, but couldn't isolate my target kitten", MU::WARN, details: caller
#         puts File.read(deploy_dir(deploy_id)+"/deployment.json")
#          end

          # We can't refine any further by asking the cloud provider...
          if !cloud_id and !tag_key and !tag_value and kittens.size > 1
            if !allow_multi
              raise MuError, "Multiple matches in MU::MommaCat.findStray where none allowed from deploy_id: '#{deploy_id}', name: '#{name}', mu_name: '#{mu_name}' (#{caller[0]})"
            else
              return kittens.values
            end
          end
        end

        matches = []

        found_the_thing = false
        credlist.each { |creds|
          break if found_the_thing
          if cloud_id or (tag_key and tag_value) or !flags.empty?
            regions = []
            begin
              if region
                regions << region
              else
                regions = cloudclass.listRegions(credentials: creds)
              end
            rescue NoMethodError # Not all cloud providers have regions
              regions = [""]
            end

            if cloud == "Google" and ["vpcs", "firewall_rules"].include?(cfg_plural)
              regions = [nil]
            end

            cloud_descs = {}
            regions.each { |r|
              cloud_descs[r] = resourceclass.find(cloud_id: cloud_id, region: r, tag_key: tag_key, tag_value: tag_value, flags: flags, credentials: creds)
              # Stop if you found the thing
              if cloud_id and cloud_descs[r] and !cloud_descs[r].empty?
                found_the_thing = true
                break
              end
            }
            regions.each { |r|
              next if cloud_descs[r].nil?
              cloud_descs[r].each_pair { |kitten_cloud_id, descriptor|
                # We already have a MU::Cloud object for this guy, use it
                if kittens.has_key?(kitten_cloud_id)
                  matches << kittens[kitten_cloud_id]
                elsif kittens.size == 0
                  if !dummy_ok
                    next
                  end
                  # If we don't have a MU::Cloud object, manufacture a dummy one.
                  # Give it a fake name if we have to and have decided that's ok.
                  if (name.nil? or name.empty?)
                    if !dummy_ok
                      MU.log "Found cloud provider data for #{cloud} #{type} #{kitten_cloud_id}, but without a name I can't manufacture a proper #{type} object to return", loglevel, details: caller
                      next
                    else
                      if !mu_name.nil?
                        name = mu_name
                      elsif !tag_value.nil?
                        name = tag_value
                      else
                        name = kitten_cloud_id
                      end
                    end
                  end
                  cfg = {
                    "name" => name,
                    "cloud" => cloud,
                    "region" => r,
                    "credentials" => creds
                  }
                  # If we can at least find the config from the deploy this will
                  # belong with, use that, even if it's an ungroomed resource.
                  if !calling_deploy.nil? and
                     !calling_deploy.original_config.nil? and
                     !calling_deploy.original_config[type+"s"].nil?
                    calling_deploy.original_config[type+"s"].each { |s|
                      if s["name"] == name
                        cfg = s.dup
                        break
                      end
                    }

                    matches << resourceclass.new(mommacat: calling_deploy, kitten_cfg: cfg, cloud_id: kitten_cloud_id)
                  else
                    matches << resourceclass.new(mu_name: name, kitten_cfg: cfg, cloud_id: kitten_cloud_id.to_s)
                  end
                end
              }
            }
          end
        }
      rescue Exception => e
        MU.log e.inspect, MU::ERR, details: e.backtrace
      end
      matches
    end

    # Return the resource object of another member of this deployment
    # @param type [String,Symbol]: The type of resource
    # @param name [String]: The name of the resource as defined in its 'name' Basket of Kittens field
    # @param mu_name [String]: The fully-resolved and deployed name of the resource
    # @param cloud_id [String]: The cloud provider's unique identifier for this resource
    # @param created_only [Boolean]: Only return the littermate if its cloud_id method returns a value
    # @param return_all [Boolean]: Return a Hash of matching objects indexed by their mu_name, instead of a single match. Only valid for resource types where has_multiples is true.
    # @return [MU::Cloud]
    def findLitterMate(type: nil, name: nil, mu_name: nil, cloud_id: nil, created_only: false, return_all: false, credentials: nil)
      shortclass, cfg_name, cfg_plural, classname, attrs = MU::Cloud.getResourceNames(type)
      type = cfg_plural
      has_multiples = attrs[:has_multiples]

      @kitten_semaphore.synchronize {
        if !@kittens.has_key?(type)
          return nil
        end
        MU.log "findLitterMate(type: #{type}, name: #{name}, mu_name: #{mu_name}, cloud_id: #{cloud_id}, created_only: #{created_only}, credentials: #{credentials}). has_multiples is #{attrs[:has_multiples].to_s}. Caller: #{caller[2]}", MU::DEBUG, details: @kittens.keys.map { |k| k.to_s+": "+@kittens[k].keys.join(", ") }
        matches = []

        @kittens[type].each { |sib_class, data|
          virtual_name = nil

          if !has_multiples and data and !data.is_a?(Hash) and data.config and data.config.is_a?(Hash) and data.config['virtual_name'] and name == data.config['virtual_name']
            virtual_name = data.config['virtual_name']
          elsif !name.nil? and name != sib_class
            next
          end
          if has_multiples
            if !name.nil?
              if return_all
                return data.dup
              end
              if data.size == 1 and (cloud_id.nil? or data.values.first.cloud_id == cloud_id)
                obj = data.values.first
                return obj
              elsif mu_name.nil? and cloud_id.nil?
                obj = data.values.first
                MU.log "#{@deploy_id}: Found multiple matches in findLitterMate based on #{type}: #{name}, and not enough info to narrow down further. Returning an arbitrary result. Caller: #{caller[2]}", MU::WARN, details: data.keys
                return data.values.first
              end
            end
            data.each_pair { |sib_mu_name, obj|
              if (!mu_name.nil? and mu_name == sib_mu_name) or
                  (!cloud_id.nil? and cloud_id == obj.cloud_id) or
                  (!credentials.nil? and credentials == obj.credentials)
                if !created_only or !obj.cloud_id.nil?
                  if return_all
                    return data.dup
                  else
                    return obj
                  end
                end
              end
            }
          else
            if (name.nil? or sib_class == name or virtual_name == name) and
                (cloud_id.nil? or cloud_id == data.cloud_id) and
                (credentials.nil? or data.credentials.nil? or credentials == data.credentials)
              matches << data if !created_only or !data.cloud_id.nil?
            end
          end
        }

        return matches.first if matches.size == 1
        if return_all and matches.size > 1
          return matches
        end
      }


      return nil
    end

    # Add or remove a resource's metadata to this deployment's structure and
    # flush it to disk.
    # @param type [String]: The type of resource (e.g. *server*, *database*).
    # @param key [String]: The name field of this resource.
    # @param data [Hash]: The resource's metadata.
    # @param remove [Boolean]: Remove this resource from the deploy structure, instead of adding it.
    # @return [void]
    def notify(type, key, data, mu_name: nil, remove: false, triggering_node: nil, delayed_save: false)
      return if @no_artifacts
      MU::MommaCat.lock("deployment-notification")
      loadDeploy(true) # make sure we're saving the latest and greatest
      have_deploy = true
      shortclass, cfg_name, cfg_plural, classname, attrs = MU::Cloud.getResourceNames(type)
      has_multiples = false

      # it's not always the case that we're logging data for a legal resource
      # type, though that's what we're usually for
      if cfg_plural
        type = cfg_plural
        has_multiples = attrs[:has_multiples]
      end

      if mu_name.nil?
        if !data.nil? and !data["mu_name"].nil?
          mu_name = data["mu_name"]
        elsif !triggering_node.nil? and !triggering_node.mu_name.nil?
          mu_name = triggering_node.mu_name
        end
        if mu_name.nil? and has_multiples
          MU.log "MU::MommaCat.notify called to modify deployment struct for a type (#{type}) with :has_multiples, but no mu_name available to look under #{key}. Call was #{caller[0]}", MU::WARN, details: data
          MU::MommaCat.unlock("deployment-notification")
          return
        end
      end

      if !remove
        if data.nil?
          MU.log "MU::MommaCat.notify called to modify deployment struct, but no data provided", MU::WARN
          MU::MommaCat.unlock("deployment-notification")
          return
        end
        @deployment[type] = {} if @deployment[type].nil?
        if has_multiples
          @deployment[type][key] = {} if @deployment[type][key].nil?
          # fix has_multiples classes that weren't tiered correctly
          if @deployment[type][key].is_a?(Hash) and @deployment[type][key].has_key?("mu_name")
            olddata = @deployment[type][key].dup
            @deployment[type][key][olddata["mu_name"]] = olddata
          end
          @deployment[type][key][mu_name] = data
          MU.log "Adding to @deployment[#{type}][#{key}][#{mu_name}]", MU::DEBUG, details: data
        else
          @deployment[type][key] = data
          MU.log "Adding to @deployment[#{type}][#{key}]", MU::DEBUG, details: data
        end
        save!(key) if !delayed_save
      else
        have_deploy = true
        if @deployment[type].nil? or @deployment[type][key].nil?

          if has_multiples
            MU.log "MU::MommaCat.notify called to remove #{type} #{key} #{mu_name} deployment struct, but no such data exist", MU::DEBUG
          else
            MU.log "MU::MommaCat.notify called to remove #{type} #{key} deployment struct, but no such data exist", MU::DEBUG
          end
          MU::MommaCat.unlock("deployment-notification")

          return
        end

        if have_deploy
          if has_multiples
            MU.log "Removing @deployment[#{type}][#{key}][#{mu_name}]", MU::DEBUG, details: @deployment[type][key][mu_name]
            @deployment[type][key].delete(mu_name)
            if @deployment[type][key].size == 0
              @deployment[type].delete(key)
            end
          else
            MU.log "Removing @deployment[#{type}][#{key}]", MU::DEBUG, details: @deployment[type][key]
            @deployment[type].delete(key)
          end
          if @deployment[type].size == 0
            @deployment.delete(type)
          end
        end
        save! if !delayed_save

      end
      MU::MommaCat.unlock("deployment-notification")
    end

    # Tag a resource. Defaults to applying our MU deployment identifier, if no
    # arguments other than the resource identifier are given.
    # XXX this belongs in the cloud layer(s)
    #
    # @param resource [String]: The cloud provider identifier of the resource to tag
    # @param tag_name [String]: The name of the tag to create
    # @param tag_value [String]: The value of the tag
    # @param region [String]: The cloud provider region
    # @return [void]
    def self.createTag(resource = nil,
        tag_name="MU-ID",
        tag_value=MU.deploy_id,
        region: MU.curRegion,
        credentials: nil)
      attempts = 0

      if !MU::Cloud::CloudFormation.emitCloudFormation
        begin
          MU::Cloud::AWS.ec2(credentials: credentials, region: region).create_tags(
            resources: [resource],
            tags: [
              {
                key: tag_name,
                value: tag_value
              }
            ]
          )
        rescue Aws::EC2::Errors::ServiceError => e
          MU.log "Got #{e.inspect} tagging #{resource} with #{tag_name}=#{tag_value}", MU::WARN if attempts > 1
          if attempts < 5
            attempts = attempts + 1
            sleep 15
            retry
          else
            raise e
          end
        end
        MU.log "Created tag #{tag_name} with value #{tag_value} for resource #{resource}", MU::DEBUG
      else
        return {
          "Key" =>  tag_name,
          "Value" => tag_value
        }
      end
    end

    # List the name/value pairs for our mandatory standard set of resource tags, which
    # should be applied to all taggable cloud provider resources.
    # @return [Hash<String,String>]
    def self.listStandardTags
      return {
          "MU-ID" => MU.deploy_id,
          "MU-APP" => MU.appname,
          "MU-ENV" => MU.environment,
          "MU-MASTER-IP" => MU.mu_public_ip
      }
    end

    # List the name/value pairs of our optional set of resource tags which
    # should be applied to all taggable cloud provider resources.
    # @return [Hash<String,String>]
    def self.listOptionalTags
      return {
        "MU-HANDLE" => MU.handle,
        "MU-MASTER-NAME" => Socket.gethostname,
        "MU-OWNER" => MU.mu_user
      }
    end

    # Clean a node's entries out of ~/.ssh/config
    # @param node [String]: The node's name
    # @return [void]
    def self.removeHostFromSSHConfig(node)
      sshdir = "#{@myhome}/.ssh"
      sshconf = "#{sshdir}/config"

      if File.exists?(sshconf) and File.open(sshconf).read.match(/ #{node} /)
        MU.log "Expunging old #{node} entry from #{sshconf}", MU::DEBUG
        if !@noop
          File.open(sshconf, File::CREAT|File::RDWR, 0600) { |f|
            f.flock(File::LOCK_EX)
            newlines = Array.new
            delete_block = false
            f.readlines.each { |line|
              if line.match(/^Host #{node}(\s|$)/)
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

    # Make sure the given node has proper DNS entries, /etc/hosts entries,
    # SSH config entries, etc.
    # @param server [MU::Cloud::Server]: The {MU::Cloud::Server} we'll be setting up.
    # @param sync_wait [Boolean]: Whether to wait for DNS to fully synchronize before returning.
    def self.nameKitten(server, sync_wait: false)
      node, config, deploydata = server.describe
      nat_ssh_key, nat_ssh_user, nat_ssh_host, canonical_addr, ssh_user, ssh_key_name = server.getSSHConfig

      mu_zone = nil
      # XXX GCP!
      if MU::Cloud::AWS.hosted? and !MU::Cloud::AWS.isGovCloud?
        zones = MU::Cloud::DNSZone.find(cloud_id: "platform-mu")
        mu_zone = zones.values.first if !zones.nil?
      end
      if !mu_zone.nil?
        MU::Cloud::DNSZone.genericMuDNSEntry(name: node, target: server.canonicalIP, cloudclass: MU::Cloud::Server, sync_wait: sync_wait)
      else
        MU::MommaCat.addInstanceToEtcHosts(server.canonicalIP, node)
      end

## TO DO: Do DNS registration of "real" records as the last stage after the groomer completes
      if config && config['dns_records'] && !config['dns_records'].empty?
        dnscfg = config['dns_records'].dup
        dnscfg.each { |dnsrec|
          if !dnsrec.has_key?('name')
            dnsrec['name'] = node.downcase
            dnsrec['name'] = "#{dnsrec['name']}.#{MU.environment.downcase}" if dnsrec["append_environment_name"] && !dnsrec['name'].match(/\.#{MU.environment.downcase}$/)
          end

          if !dnsrec.has_key?("target")
            # Default to register public endpoint
            public = true

            if dnsrec.has_key?("target_type")
              # See if we have a preference for pubic/private endpoint
              public = dnsrec["target_type"] == "private" ? false : true
            end
  
            dnsrec["target"] =
              if dnsrec["type"] == "CNAME"
                if public
                  # Make sure we have a public canonical name to register. Use the private one if we don't
                  server.cloud_desc.public_dns_name.empty? ? server.cloud_desc.private_dns_name : server.cloud_desc.public_dns_name
                else
                  # If we specifically requested to register the private canonical name lets use that
                  server.cloud_desc.private_dns_name
                end
              elsif dnsrec["type"] == "A"
                if public
                  # Make sure we have a public IP address to register. Use the private one if we don't
                  server.cloud_desc.public_ip_address ? server.cloud_desc.public_ip_address : server.cloud_desc.private_ip_address
                else
                  # If we specifically requested to register the private IP lets use that
                  server.cloud_desc.private_ip_address
                end
              end
          end
        }
        if !MU::Cloud::AWS.isGovCloud?
          MU::Cloud::DNSZone.createRecordsFromConfig(dnscfg)
        end
      end

      MU::MommaCat.removeHostFromSSHConfig(node)
# XXX add names paramater with useful stuff
      MU::MommaCat.addHostToSSHConfig(
          server,
          ssh_owner: server.deploy.mu_user,
          ssh_dir: Etc.getpwnam(server.deploy.mu_user).dir+"/.ssh"
      )
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
        ssh_dir: "#{@myhome}/.ssh",
        ssh_conf: "#{@myhome}/.ssh/config",
        ssh_owner: Etc.getpwuid(Process.uid).name,
        names: [],
        timeout: 0
    )
      if server.nil?
        MU.log "Called addHostToSSHConfig without a MU::Cloud::Server object", MU::ERR, details: caller
        return nil
      end
      begin
        nat_ssh_key, nat_ssh_user, nat_ssh_host, canonical_ip, ssh_user, ssh_key_name = server.getSSHConfig
      rescue MU::MuError => e
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
        MU.log "Failed to extract canonical_ip for #{ssh_key_name.mu_name} in addHostToSSHConfig", MU::ERR
        return
      end

      @ssh_semaphore.synchronize {

        if File.exists?(ssh_conf)
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
      return if !["mu", "root"].include?(MU.mu_user)

      # XXX cover ipv6 case
      if public_ip.nil? or !public_ip.match(/^\d+\.\d+\.\d+\.\d+$/) or (chef_name.nil? and system_name.nil?)
        raise MuError, "addInstanceToEtcHosts requires public_ip and one or both of chef_name and system_name!"
      end
      if chef_name == "localhost" or system_name == "localhost"
        raise MuError, "Can't set localhost as a name in addInstanceToEtcHosts"
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


    # Send a Slack notification to a deployment's administrators.
    # @param subject [String]: The subject line of the message.
    # @param msg [String]: The message body.
    # @return [void]
    def sendAdminSlack(subject, msg: "")
      if $MU_CFG['slack'] and $MU_CFG['slack']['webhook'] and
         (!$MU_CFG['slack']['skip_environments'] or !$MU_CFG['slack']['skip_environments'].any?{ |s| s.casecmp(MU.environment)==0 })
        require 'slack-notifier'
        slack =  Slack::Notifier.new $MU_CFG['slack']['webhook']

        if msg and !msg.empty?
          slack.ping "#{MU.appname} \*\"#{MU.handle}\"\* (`#{MU.deploy_id}`) - #{subject}:\n\n```#{msg}\n```", channel: $MU_CFG['slack']['channel']
        else
          slack.ping "#{MU.appname} \*\"#{MU.handle}\"\* (`#{MU.deploy_id}`) - #{subject}", channel: $MU_CFG['slack']['channel']
        end
      end
    end

    # Send an email notification to a deployment's administrators.
    # @param subject [String]: The subject line of the message.
    # @param msg [String]: The message body.
    # @param data [Array]: Supplemental data to add to the message body.
    # @param debug [Boolean]: If set, will include the full deployment structure and original {MU::Config}-parsed configuration.
    # @return [void]
    def sendAdminMail(subject, msg: msg = "", kitten: nil, data: nil, debug: debug = false)
      require 'net/smtp'
      if @deployment.nil?
        MU.log "Can't send admin mail without a loaded deployment", MU::ERR
        return
      end
      to = Array.new
      if !@original_config.nil?
        @original_config['admins'].each { |admin|
          to << "#{admin['name']} <#{admin['email']}>"
        }
      end
      message = <<MESSAGE_END
From: #{MU.handle} <root@localhost>
To: #{to.join(",")}
Subject: #{subject}

      #{msg}
MESSAGE_END
      if !kitten.nil? and kitten.kind_of?(MU::Cloud)
        message = message + "\n\n**** #{kitten}:\n"
        if !kitten.report.nil?
          kitten.report.each { |line|
            message = message + line
          }
        end
      end
      if !data.nil?
        message = message + "\n\n" + PP.pp(data, "")
      end
      if debug
        message = message + "\n\n**** Stack configuration:\n" + PP.pp(@original_config, "")
        message = message + "\n\n**** Deployment structure:\n" + PP.pp(@deployment, "")
      end
      begin
        Net::SMTP.start('localhost') do |smtp|
          smtp.send_message message, "root@localhost", to
        end
      rescue Net::SMTPFatalError, Errno::ECONNREFUSED => e
        MU.log e.inspect, MU::WARN
      end
    end

    # Manufactures a human-readable deployment name from the random
    # two-character seed in MU-ID. Cat-themed when possible.
    # @param seed [String]: A two-character seed from which we'll generate a name.
    # @return [String]: Two words
    def self.generateHandle(seed)
      word_one=word_two=nil

      # Unless we've got two letters that don't have corresponding cat-themed
      # words, we'll insist that our generated handle have at least one cat
      # element to it.
      require_cat_words = true
      if @catwords.select { |word| word.match(/^#{seed[0]}/i) }.size == 0 and
          @catwords.select { |word| word.match(/^#{seed[1]}/i) }.size == 0
        require_cat_words = false
        MU.log "Got an annoying pair of letters #{seed}, not forcing cat-theming", MU::DEBUG
      end
      allnouns = @catnouns + @jaegernouns
      alladjs = @catadjs + @jaegeradjs

      tries = 0
      begin
        # Try to avoid picking something "nouny" for the first word
        source = @catadjs + @catmixed + @jaegeradjs + @jaegermixed
        first_ltr = source.select { |word| word.match(/^#{seed[0]}/i) }
        if !first_ltr or first_ltr.size == 0
          first_ltr = @words.select { |word| word.match(/^#{seed[0]}/i) }
        end
        word_one = first_ltr.shuffle.first

        # If we got a paired set that happen to match our letters, go with it
        if !word_one.nil? and word_one.match(/-#{seed[1]}/i)
          word_one, word_two = word_one.split(/-/)
        else
          source = @words
          if @catwords.include?(word_one)
            source = @jaegerwords
          elsif require_cat_words
            source = @catwords
          end
          second_ltr = source.select { |word| word.match(/^#{seed[1]}/i) and !word.match(/-/i) }
          word_two = second_ltr.shuffle.first
        end
        tries = tries + 1
      end while tries < 50 and (word_one.nil? or word_two.nil? or word_one.match(/-/) or word_one == word_two or (allnouns.include?(word_one) and allnouns.include?(word_two)) or (alladjs.include?(word_one) and alladjs.include?(word_two)) or (require_cat_words and !@catwords.include?(word_one) and !@catwords.include?(word_two)))

      if tries >= 50 and (word_one.nil? or word_two.nil?)
        MU.log "I failed to generated a valid handle, faking it", MU::ERR
        return "#{seed[0].capitalize} #{seed[1].capitalize}"
      end

      return "#{word_one.capitalize} #{word_two.capitalize}"
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
        [@nagios_home, "#{@nagios_home}/.ssh"].each { |dir|
          Dir.mkdir(dir, 0711) if !Dir.exists?(dir)
          File.chown(Etc.getpwnam("nagios").uid, Etc.getpwnam("nagios").gid, dir)
        }
        if realhome != @nagios_home and Dir.exists?(realhome) and !File.symlink?("#{realhome}/.ssh")
          File.rename("#{realhome}/.ssh", "#{realhome}/.ssh.#{$$}") if Dir.exists?("#{realhome}/.ssh")
          File.symlink("#{@nagios_home}/.ssh", Etc.getpwnam("nagios").dir+"/.ssh")
        end
        MU.log "Updating #{@nagios_home}/.ssh/config..."
        ssh_lock = File.new("#{@nagios_home}/.ssh/config.mu.lock", File::CREAT|File::TRUNC|File::RDWR, 0600)
        ssh_lock.flock(File::LOCK_EX)
        ssh_conf = File.new("#{@nagios_home}/.ssh/config.tmp", File::CREAT|File::TRUNC|File::RDWR, 0600)
        ssh_conf.puts "Host MU-MASTER localhost"
        ssh_conf.puts "  Hostname localhost"
        ssh_conf.puts "  User root"
        ssh_conf.puts "  IdentityFile #{@nagios_home}/.ssh/id_rsa"
        ssh_conf.puts "  StrictHostKeyChecking no"
        ssh_conf.close
        FileUtils.cp("#{@myhome}/.ssh/id_rsa", "#{@nagios_home}/.ssh/id_rsa")
        File.chown(Etc.getpwnam("nagios").uid, Etc.getpwnam("nagios").gid, "#{@nagios_home}/.ssh/id_rsa")
        threads = []
        if !MU::Cloud::AWS.isGovCloud?
          mu_zone = MU::Cloud::DNSZone.find(cloud_id: "platform-mu").values.first
        end
# XXX what if we're in GCP?
# XXX need a MU::Cloud::DNSZone.lookup for bulk lookups
# XXX also grab things like mu_windows_name out of deploy data if we can

        parent_thread_id = Thread.current.object_id
        MU::MommaCat.listDeploys.sort.each { |deploy_id|
          begin
            # We don't want to use cached litter information here because this is also called by cleanTerminatedInstances.
            deploy = MU::MommaCat.getLitter(deploy_id, use_cache: false)
            if deploy.ssh_key_name.nil? or deploy.ssh_key_name.empty?
              MU.log "Failed to extract ssh key name from #{deploy_id} in syncMonitoringConfig", MU::ERR if deploy.kittens.has_key?("servers")
              next
            end
            FileUtils.cp("#{@myhome}/.ssh/#{deploy.ssh_key_name}", "#{@nagios_home}/.ssh/#{deploy.ssh_key_name}")
            File.chown(Etc.getpwnam("nagios").uid, Etc.getpwnam("nagios").gid, "#{@nagios_home}/.ssh/#{deploy.ssh_key_name}")
            if deploy.kittens.has_key?("servers")
              deploy.kittens["servers"].each_pair { |nodeclass, nodes|
                nodes.each_pair { |mu_name, server|
                  MU.dupGlobals(parent_thread_id)
                  threads << Thread.new {
                    MU::MommaCat.setThreadContext(deploy)
                    MU.log "Adding #{server.mu_name} to #{@nagios_home}/.ssh/config", MU::DEBUG
                    MU::MommaCat.addHostToSSHConfig(
                        server,
                        ssh_dir: "#{@nagios_home}/.ssh",
                        ssh_conf: "#{@nagios_home}/.ssh/config.tmp",
                        ssh_owner: "nagios"
                    )
                    MU.purgeGlobals
                  }
                }
              }
            end
          rescue Exception => e
            MU.log "#{e.inspect} while generating Nagios SSH config in #{deploy_id}", MU::ERR, details: e.backtrace
          end
        }
        threads.each { |t|
          t.join
        }
        ssh_lock.flock(File::LOCK_UN)
        ssh_lock.close
        File.chown(Etc.getpwnam("nagios").uid, Etc.getpwnam("nagios").gid, "#{@nagios_home}/.ssh/config.tmp")
        File.rename("#{@nagios_home}/.ssh/config.tmp", "#{@nagios_home}/.ssh/config")

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

    # Return a list of all currently active deploy identifiers.
    # @return [Array<String>]
    def self.listDeploys
      return [] if !Dir.exists?("#{MU.dataDir}/deployments")
      deploys = []
      Dir.entries("#{MU.dataDir}/deployments").reverse_each { |muid|
        next if !Dir.exists?("#{MU.dataDir}/deployments/#{muid}") or muid == "." or muid == ".."
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
          if !Dir.exists?(MU::MommaCat.deploy_dir(deploy)) or
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
            MU.log "JSON parse failed on #{MU::MommaCat.deploy_dir(deploy)}/deployment.json", MU::ERR
          end
          data.flock(File::LOCK_UN)
          data.close
        }
      }
      return nodes
    end

    # Return a list of all nodes associated with the current deployment.
    # @return [Hash]
    def listNodes
      nodes = Hash.new
      if !@deployment['servers'].nil?
        @deployment['servers'].each_pair { |nodetype, node|
          node.each_pair { |name, metadata|
            if name.nil? or metadata.nil? or !metadata.is_a?(Hash)
              MU.log "Original config of deploy #{MU.deploy_id} looks funny. It's probably very old.", MU::WARN
              next
            end
            metadata['deploy_id'] = MU.deploy_id
            nodes[name] = metadata
            ['servers', 'server_pools'].each { |res_type|
              if !@original_config[res_type].nil?
                @original_config[res_type].each { |srv_conf|
                  if srv_conf['name'] == nodetype
                    nodes[name]['conf'] = srv_conf.dup
                  end
                }
              end
            }
          }
        }
      end

      return nodes
    end

    # For a given (Windows) server, return it's administrator user and password.
    # This is generally for requests made to MommaCat from said server, which
    # we can assume have been authenticated with the deploy secret.
    # @param server [MU::Cloud::Server]: The Server object whose credentials we're fetching.
    def retrieveWindowsAdminCreds(server)
      if server.nil?
        raise MuError, "retrieveWindowsAdminCreds must be called with a Server object"
      elsif !server.is_a?(MU::Cloud::Server)
        raise MuError, "retrieveWindowsAdminCreds must be called with a Server object (got #{server.class.name})"
      end
      if server.config['use_cloud_provider_windows_password']
        return [server.config["windows_admin_username"], server.getWindowsAdminPassword]
      elsif server.config['windows_auth_vault'] && !server.config['windows_auth_vault'].empty?
        if server.config["windows_auth_vault"].has_key?("password_field")
          return [server.config["windows_admin_username"],
            server.groomer.getSecret(
              vault: server.config['windows_auth_vault']['vault'],
              item: server.config['windows_auth_vault']['item'],
              field: server.config["windows_auth_vault"]["password_field"]
            )]
        else
          return [server.config["windows_admin_username"], server.getWindowsAdminPassword]
        end
      end
      []
    end

    # Given a Certificate Signing Request, sign it with our internal CA and
    # write the resulting signed certificate. Only works on local files.
    # @param csr_path [String]: The CSR to sign, as a file.
    def signSSLCert(csr_path, sans = [])
      MU::Master::SSL.sign(csr_path, sans, for_user: MU.mu_user)
    end

    # Make sure deployment data is synchronized to/from each node in the
    # currently-loaded deployment.
    def syncLitter(nodeclasses = [], triggering_node: nil, save_all_only: false)
# XXX take some config logic to decide what nodeclasses to hit
# XXX don't run on triggering node, duh
      return if MU.syncLitterThread
      return if !Dir.exists?(deploy_dir)
      svrs = MU::Cloud.resource_types[:Server][:cfg_plural] # legibility shorthand

      @kitten_semaphore.synchronize {
        if @kittens.nil? or
            @kittens[svrs].nil?
          MU.log "No #{svrs} as yet available in #{@deploy_id}", MU::DEBUG, details: @kittens
          return
        end

        MU.log "Updating these siblings in #{@deploy_id}: #{nodeclasses.join(', ')}", MU::DEBUG, details: @kittens[svrs].map { |nodeclass, instance| instance.keys }
      }

      update_servers = []
      if nodeclasses.nil? or nodeclasses.size == 0
        litter = findLitterMate(type: "server", return_all: true)
        litter.each_pair { |mu_name, node|
          next if !triggering_node.nil? and mu_name == triggering_node.mu_name
          if !node.groomer.nil?
            update_servers << node
          end
        }
      else
        litter = {}
        nodeclasses.each { |nodeclass|
          mates = findLitterMate(type: "server", name: nodeclass, return_all: true)
          litter.merge!(mates) if mates
        }
        litter.each_pair { |mu_name, node|
          next if !triggering_node.nil? and mu_name == triggering_node.mu_name
          if !node.deploydata or !node.deploydata.keys.include?('nodename')
            details = node.deploydata ? node.deploydata.keys : nil
            MU.log "#{mu_name} deploy data is missing (possibly retired), not syncing it", MU::WARN, details: details
          else
            update_servers << node
          end
        }
      end
      return if update_servers.size == 0

      update_servers.each { |node|
        # Not clear where this pollution comes from, but let's stick a temp
        # fix in here.
        if node.deploydata['nodename'] != node.mu_name
          MU.log "Node #{node.mu_name} had wrong or missing nodename (#{node.deploydata['nodename']}), correcting", MU::WARN
          node.deploydata['nodename'] = node.mu_name
          @deployment[svrs][node.config['name']][node.mu_name]['nodename'] = node.mu_name
          save!
        end
      }

      # Merge everyone's deploydata together
      if !save_all_only
        skip = []
        update_servers.each { |node|
          if node.mu_name.nil? or node.deploydata.nil? or node.config.nil?
            MU.log "Missing mu_name #{node.mu_name}, deploydata, or config from #{node} in syncLitter", MU::ERR, details: node.deploydata
            next
          end

          if !@deployment[svrs][node.config['name']].has_key?(node.mu_name) or @deployment[svrs][node.config['name']][node.mu_name] != node.deploydata
            @deployment[svrs][node.config['name']][node.mu_name] = node.deploydata
          else
            skip << node
          end
        }
        update_servers = update_servers - skip
      end

      return if update_servers.size < 1
      threads = []
      parent_thread_id = Thread.current.object_id
      update_servers.each { |sibling|
        threads << Thread.new {
          Thread.abort_on_exception = true
          MU.dupGlobals(parent_thread_id)
          Thread.current.thread_variable_set("name", "sync-"+sibling.mu_name.downcase)
          MU.setVar("syncLitterThread", true)
          begin
            if sibling.config['groom'].nil? or sibling.config['groom']
              sibling.groomer.saveDeployData
              sibling.groomer.run(purpose: "Synchronizing sibling kittens") if !save_all_only
            end
          rescue MU::Groomer::RunError => e
            MU.log "Sync of #{sibling.mu_name} failed: #{e.inspect}", MU::WARN
          end
          MU.purgeGlobals
        }
      }

      threads.each { |t|
        t.join
      }

      MU.log "Synchronization of #{@deploy_id} complete", MU::DEBUG, details: update_servers
    end

    @node_cert_semaphore = nil
    # Given a MU::Cloud object, return the generic self-signed SSL
    # certficate we made for it. If one doesn't exist yet, generate it first.
    # If it's a Windows node, also generate a certificate for WinRM client auth.
    # @param resource [MU::Cloud]: The server or other MU::Cloud resource object for which to generate or return the cert
    # @param poolname [Boolean]: If true, generate certificates for the base name of the server pool of which this node is a member, rather than for the individual node
    # @param keysize [Integer]: The size of the private key to use when generating this certificate
    def nodeSSLCerts(resource, poolname = false, keysize = 4096)
      nat_ssh_key, nat_ssh_user, nat_ssh_host, canonical_ip, ssh_user, ssh_key_name = resource.getSSHConfig if resource.respond_to?(:getSSHConfig)

      deploy_id = resource.deploy_id || @deploy_id || resource.deploy.deploy_id

      cert_cn = poolname ? deploy_id + "-" + resource.config['name'].upcase : resource.mu_name

      certs = {}
      results = {}

      is_windows = ([MU::Cloud::Server, MU::Cloud::AWS::Server, MU::Cloud::Google::Server].include?(resource.class) and resource.windows?)
      is_windows = true

      @node_cert_semaphore.synchronize {
        MU::Master::SSL.bootstrap
        sans = []
        sans << canonical_ip if canonical_ip
        # XXX were there other names we wanted to include?
        key = MU::Master::SSL.getKey(cert_cn)
        cert, pfx_cert = MU::Master::SSL.getCert(cert_cn, "/CN=#{cert_cn}/O=Mu/C=US", sans: sans, pfx: is_windows)
        results[cert_cn] = [key, cert]

        winrm_cert = nil
        if is_windows
          winrm_key = MU::Master::SSL.getKey(cert_cn+"-winrm")
          winrm_cert = MU::Master::SSL.getCert(cert_cn+"-winrm", "/CN=#{resource.config['windows_admin_username']}/O=Mu/C=US", sans: ["otherName:1.3.6.1.4.1.311.20.2.3;UTF8:#{resource.config['windows_admin_username']}@localhost"], pfx: true)
          results[cert_cn+"-winrm"] = [winrm_key, winrm_cert]
        end

        if resource and resource.config and resource.config['cloud']
          cloudclass = Object.const_get("MU").const_get("Cloud").const_get(resource.config['cloud'])

          cloudclass.writeDeploySecret(@deploy_id, cert.to_pem, cert_cn+".crt")
          cloudclass.writeDeploySecret(@deploy_id, key.to_pem, cert_cn+".key")
          if pfx_cert
            cloudclass.writeDeploySecret(@deploy_id, pfx_cert.to_der, cert_cn+".pfx")
          end
        end

      }

      results[cert_cn]
    end

    # @return [String]: The Mu Master filesystem directory holding metadata for the current deployment
    def deploy_dir
      MU::MommaCat.deploy_dir(@deploy_id)
    end

    # Path to the log file used by the Momma Cat daemon
    # @return [String]
    def self.daemonLogFile
      base = Process.uid == 0 ? "/var" : MU.dataDir
      "#{base}/log/mu-momma-cat.log"
    end

    # Path to the PID file used by the Momma Cat daemon
    # @return [String]
    def self.daemonPidFile
      base = Process.uid == 0 ? "/var" : MU.dataDir
      "#{base}/run/mommacat.pid"
    end

		# Start the Momma Cat daemon and return the exit status of the command used
    # @return [Integer]
    def self.start
      base = Process.uid == 0 ? "/var" : MU.dataDir
      [base, "#{base}/log", "#{base}/run"].each { |dir|
       if !Dir.exists?(dir)
          MU.log "Creating #{dir}"
          Dir.mkdir(dir)
        end
      }
      return 0 if status
    
      MU.log "Starting Momma Cat on port #{MU.mommaCatPort}, logging to #{daemonLogFile}"
      origdir = Dir.getwd
      Dir.chdir(MU.myRoot+"/modules")

      # XXX what's the safest way to find the 'bundle' executable in both gem and non-gem installs?
      cmd = %Q{bundle exec thin --threaded --daemonize --port #{MU.mommaCatPort} --pid #{daemonPidFile} --log #{daemonLogFile} --ssl --ssl-key-file #{MU.mySSLDir}/mommacat.key --ssl-cert-file #{MU.mySSLDir}/mommacat.pem --ssl-disable-verify --tag mu-momma-cat -R mommacat.ru start}
      MU.log cmd, MU::DEBUG
      %x{#{cmd}}
      Dir.chdir(origdir)

      begin
        sleep 1
      end while !status
    
      if $?.exitstatus != 0
        exit 1
      end

      return $?.exitstatus
    end

    # Return true if the Momma Cat daemon appears to be running
    # @return [Boolean]
    def self.status
      if File.exists?(daemonPidFile)
        pid = File.read(daemonPidFile).chomp.to_i
        begin
          Process.getpgid(pid)
          MU.log "Momma Cat running with pid #{pid.to_s}"
          return true
        rescue Errno::ESRC
        end
      end
      MU.log "Momma Cat daemon not running", MU::NOTICE
      false
    end
    
		# Stop the Momma Cat daemon, if it's running
    def self.stop
      if File.exists?(daemonPidFile)
        pid = File.read(daemonPidFile).chomp.to_i
        MU.log "Stopping Momma Cat with pid #{pid.to_s}"
        Process.kill("INT", pid)
        killed = false
        begin
          Process.getpgid(pid)
          sleep 1
        rescue Errno::ESRC
          killed = true
        end while killed
        MU.log "Momma Cat with pid #{pid.to_s} stopped", MU::DEBUG
    
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


    private

    # Check to see whether a given resource name is unique across all
    # deployments on this Mu server. We only enforce this for certain classes
    # of names. If the name in question is available, add it to our cache of
    # said names.  See #{MU::MommaCat.getResourceName}
    # @param name [String]: The name to attempt to allocate.
    # @return [Boolean]: True if allocation was successful.
    def allocateUniqueResourceName(name)
      raise MuError, "Cannot call allocateUniqueResourceName without an active deployment" if @deploy_id.nil?
      path = File.expand_path(MU.dataDir+"/deployments")
      File.open(path+"/unique_ids", File::CREAT|File::RDWR, 0600) { |f|
        existing = []
        f.flock(File::LOCK_EX)
        f.readlines.each { |line|
          existing << line.chomp
        }
        begin
          existing.each { |used|
            if used.match(/^#{name}:/)
              if !used.match(/^#{name}:#{@deploy_id}$/)
                MU.log "#{name} is already reserved by another resource on this Mu server.", MU::WARN, details: caller
                return false
              else
                return true
              end
            end
          }
          f.puts name+":"+@deploy_id
          return true
        ensure
          f.flock(File::LOCK_UN)
        end
      }
    end

    ###########################################################################
    ###########################################################################
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

    def self.deploy_exists?(deploy_id)
      if deploy_id.nil? or deploy_id.empty?
        MU.log "Got nil deploy_id in MU::MommaCat.deploy_exists?", MU::WARN
        return
      end
      path = File.expand_path(MU.dataDir+"/deployments")
      if !Dir.exists?(path)
        Dir.mkdir(path, 0700)
      end
      deploy_path = File.expand_path(path+"/"+deploy_id)
      return Dir.exist?(deploy_path)
    end


    def createDeployKey
      key = OpenSSL::PKey::RSA.generate(4096)
      MU.log "Generated deploy key for #{MU.deploy_id}", MU::DEBUG, details: key.public_key.export
      return [key.export, key.public_key.export]
    end

    # Synchronize all in-memory information related to this to deployment to
    # disk.
    def save!(triggering_node = nil)
      return if @no_artifacts
      MU::MommaCat.deploy_struct_semaphore.synchronize {
        MU.log "Saving deployment #{MU.deploy_id}", MU::DEBUG

        if !Dir.exist?(deploy_dir)
          MU.log "Creating #{deploy_dir}", MU::DEBUG
          Dir.mkdir(deploy_dir, 0700)
        end

        if !@private_key.nil?
          privkey = File.new("#{deploy_dir}/private_key", File::CREAT|File::TRUNC|File::RDWR, 0600)
          privkey.puts @private_key
          privkey.close
        end

        if !@public_key.nil?
          pubkey = File.new("#{deploy_dir}/public_key", File::CREAT|File::TRUNC|File::RDWR, 0600)
          pubkey.puts @public_key
          pubkey.close
        end

        if !@deployment.nil? and @deployment.size > 0
          @deployment['handle'] = MU.handle if @deployment['handle'].nil? and !MU.handle.nil?
          @deployment['public_key'] = @public_key
          begin
            # XXX doing this to trigger JSON errors before stomping the stored
            # file...
            JSON.pretty_generate(@deployment, max_nesting: false)
            deploy = File.new("#{deploy_dir}/deployment.json", File::CREAT|File::TRUNC|File::RDWR, 0600)
            MU.log "Getting lock to write #{deploy_dir}/deployment.json", MU::DEBUG
            deploy.flock(File::LOCK_EX)
            deploy.puts JSON.pretty_generate(@deployment, max_nesting: false)
          rescue JSON::NestingError => e
            raise MuError, e.inspect+"\n\n"+@deployment.to_s
          end
          deploy.flock(File::LOCK_UN)
          deploy.close
        end

        if !@original_config.nil? and @original_config.is_a?(Hash)
          config = File.new("#{deploy_dir}/basket_of_kittens.json", File::CREAT|File::TRUNC|File::RDWR, 0600)
          config.puts JSON.pretty_generate(@original_config)
          config.close
        end

        if !@ssh_private_key.nil?
          key = File.new("#{deploy_dir}/node_ssh.key", File::CREAT|File::TRUNC|File::RDWR, 0600)
          key.puts @ssh_private_key
          key.close
        end
        if !@ssh_public_key.nil?
          key = File.new("#{deploy_dir}/node_ssh.pub", File::CREAT|File::TRUNC|File::RDWR, 0600)
          key.puts @ssh_public_key
          key.close
        end
        if !@ssh_key_name.nil?
          key = File.new("#{deploy_dir}/ssh_key_name", File::CREAT|File::TRUNC|File::RDWR, 0600)
          key.puts @ssh_key_name
          key.close
        end
        if !@environment.nil?
          env = File.new("#{deploy_dir}/environment_name", File::CREAT|File::TRUNC|File::RDWR, 0600)
          env.puts @environment
          env.close
        end
        if !@deploy_secret.nil?
          secret = File.new("#{deploy_dir}/deploy_secret", File::CREAT|File::TRUNC|File::RDWR, 0600)
          secret.print @deploy_secret
          secret.close
        end
        if !@secrets.nil?
          secretdir = "#{deploy_dir}/secrets"
          if !Dir.exist?(secretdir)
            MU.log "Creating #{secretdir}", MU::DEBUG
            Dir.mkdir(secretdir, 0700)
          end
          @secrets.each_pair { |type, server|
            server.each_pair { |server, secret|
              key = File.new("#{secretdir}/#{type}.#{server}", File::CREAT|File::TRUNC|File::RDWR, 0600)
              key.puts secret
              key.close
            }
          }
        end
      }

      # Update groomer copies of this metadata
      syncLitter(@deployment['servers'].keys, save_all_only: true) if @deployment.has_key?("servers")
    end

    # Find one or more resources by their Mu resource name, and return
    # MommaCat objects for their containing deploys, their BoK config data,
    # and their deployment data.
    #
    # @param type [String]: The type of resource, e.g. "vpc" or "server."
    # @param name [String]: The Mu resource class, typically the name field of a Basket of Kittens resource declaration.
    # @param mu_name [String]: The fully-expanded Mu resource name, e.g. MGMT-PROD-2015040115-FR-ADMGMT2
    # @param deploy_id [String]: The deployment to search. Will search all deployments if not specified.
    # @return [Hash,Array<Hash>]
    def self.getResourceMetadata(type, name: nil, deploy_id: nil, use_cache: true, mu_name: nil)
      if type.nil?
        raise MuError, "Can't call getResourceMetadata without a type argument"
      end
      shortclass, cfg_name, cfg_plural, classname = MU::Cloud.getResourceNames(type)
      type = cfg_plural

      deploy_root = File.expand_path(MU.dataDir+"/deployments")
      MU::MommaCat.deploy_struct_semaphore.synchronize {
        if Dir.exists?(deploy_root)
          Dir.entries(deploy_root).each { |deploy|
            this_deploy_dir = deploy_root+"/"+deploy
            next if deploy == "." or deploy == ".." or !Dir.exists?(this_deploy_dir)
            next if deploy_id and deploy_id != deploy

            if !File.size?(this_deploy_dir+"/deployment.json")
              MU.log "#{this_deploy_dir}/deployment.json doesn't exist, skipping when loading cache", MU::DEBUG
              next
            end
            if @deploy_cache[deploy].nil? or !use_cache
              @deploy_cache[deploy] = Hash.new
            elsif @deploy_cache[deploy]['mtime'] == File.mtime("#{this_deploy_dir}/deployment.json")
              MU.log "Using cached copy of deploy #{deploy} from #{@deploy_cache[deploy]['mtime']}", MU::DEBUG

              next
            end

            @deploy_cache[deploy] = Hash.new if !@deploy_cache.has_key?(deploy)
            MU.log "Caching deploy #{deploy}", MU::DEBUG
            lock = File.open("#{this_deploy_dir}/deployment.json", File::RDONLY)
            lock.flock(File::LOCK_EX)
            @deploy_cache[deploy]['mtime'] = File.mtime("#{this_deploy_dir}/deployment.json")

            begin
              @deploy_cache[deploy]['data'] = JSON.parse(File.read("#{this_deploy_dir}/deployment.json"))
              lock.flock(File::LOCK_UN)

              next if @deploy_cache[deploy].nil? or @deploy_cache[deploy]['data'].nil?
              # Populate some generable entries that should be in the deploy
              # data. Also, bounce out if we realize we've found exactly what
              # we needed already.
              MU::Cloud.resource_types.each_pair { |res_type, attrs|

                next if @deploy_cache[deploy]['data'][attrs[:cfg_plural]].nil?
                if !attrs[:has_multiples]
                  @deploy_cache[deploy]['data'][attrs[:cfg_plural]].each_pair { |nodename, data|
# XXX we don't actually store node names for some resources, need to farm them
# and fix metadata
#                 if !mu_name.nil? and nodename == mu_name
#                   return { deploy => [data] }
#                 end
                  }
                else
                  @deploy_cache[deploy]['data'][attrs[:cfg_plural]].each_pair { |node_class, nodes|
                    next if nodes.nil? or !nodes.is_a?(Hash)
                    nodes.each_pair { |nodename, data|
                      next if !data.is_a?(Hash)
                      data['#MU_NODE_CLASS'] = node_class
                      if !data.has_key?("cloud") # XXX kludge until old metadata gets fixed
                        data["cloud"] = MU::Config.defaultCloud
                      end
                      data['#MU_NAME'] = nodename
                      if !mu_name.nil? and nodename == mu_name
                        return {deploy => [data]} if deploy_id && deploy == deploy_id
                      end
                    }
                  }
                end
              }
            rescue JSON::ParserError => e
              raise MuError, "JSON parse failed on #{this_deploy_dir}/deployment.json\n\n"+File.read("#{this_deploy_dir}/deployment.json")
            end
            lock.flock(File::LOCK_UN)
            lock.close
          }
        end
      }

      matches = {}

      if deploy_id.nil?
        @deploy_cache.each_key { |deploy|
          next if !@deploy_cache[deploy].has_key?('data')
          next if !@deploy_cache[deploy]['data'].has_key?(type)
          if !name.nil?
            next if @deploy_cache[deploy]['data'][type][name].nil?
            matches[deploy] = [] if !matches.has_key?(deploy)
            matches[deploy] << @deploy_cache[deploy]['data'][type][name].dup
          else
            matches[deploy] = [] if !matches.has_key?(deploy)
            matches[deploy].concat(@deploy_cache[deploy]['data'][type].values)
          end
        }
        return matches
      elsif !@deploy_cache[deploy_id].nil?
        if !@deploy_cache[deploy_id]['data'].nil? and
            !@deploy_cache[deploy_id]['data'][type].nil?
          if !name.nil?
            if !@deploy_cache[deploy_id]['data'][type][name].nil?
              matches[deploy_id] = [] if !matches.has_key?(deploy_id)
              matches[deploy_id] << @deploy_cache[deploy_id]['data'][type][name].dup
            else
              return matches # nothing, actually
            end
          else
            matches[deploy_id] = @deploy_cache[deploy_id]['data'][type].values
          end
        end
      end

      return matches
    end

    ###########################################################################
    ###########################################################################
    def loadDeploy(deployment_json_only = false, set_context_to_me: true)
      MU::MommaCat.deploy_struct_semaphore.synchronize {
        if File.size?(deploy_dir+"/deployment.json")
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
          rescue JSON::ParserError => e
            MU.log "JSON parse failed on #{deploy_dir}/deployment.json", MU::ERR
          end

          deploy.flock(File::LOCK_UN)
          deploy.close
          if set_context_to_me
            ["appname", "environment", "timestamp", "seed", "handle"].each { |var|
              if @deployment[var]
                if var != "handle"
                  MU.setVar(var, @deployment[var].upcase)
                else
                  MU.setVar(var, @deployment[var])
                end
              else
                MU.log "Missing global variable #{var} for #{MU.deploy_id}", MU::ERR
              end
            }
          end
          @timestamp = @deployment['timestamp']
          @seed = @deployment['seed']
          @appname = @deployment['appname']
          @handle = @deployment['handle']

          return if deployment_json_only
        end
        if File.exist?(deploy_dir+"/private_key")
          @private_key = File.read("#{deploy_dir}/private_key")
          @public_key = File.read("#{deploy_dir}/public_key")
        end
        if File.exist?(deploy_dir+"/basket_of_kittens.json")
          begin
            @original_config = JSON.parse(File.read("#{deploy_dir}/basket_of_kittens.json"))
          rescue JSON::ParserError => e
            MU.log "JSON parse failed on #{deploy_dir}/basket_of_kittens.json", MU::ERR
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
              base, server = File.basename(filename).split(/\./)

              @secrets[type][server] = File.read(filename).chomp!
            }
          }
        end
      }
    end

    @catadjs = %w{fuzzy ginger lilac chocolate xanthic wiggly itty}
    @catnouns = %w{bastet biscuits bobcat catnip cheetah chonk dot felix jaguar kitty leopard lion lynx maru mittens moggy neko nip ocelot panther patches paws phoebe purr queen roar saber sekhmet skogkatt socks sphinx spot tail tiger tom whiskers wildcat yowl floof beans ailurophile dander dewclaw grimalkin kibble quick tuft misty simba mew quat eek ziggy}
    @catmixed = %w{abyssinian angora bengal birman bobtail bombay burmese calico chartreux cheshire cornish-rex curl devon egyptian-mau feline furever fumbs havana himilayan japanese-bobtail javanese khao-manee maine-coon manx marmalade mau munchkin norwegian pallas persian peterbald polydactyl ragdoll russian-blue savannah scottish-fold serengeti shorthair siamese siberian singapura snowshoe stray tabby tonkinese tortoiseshell turkish-van tuxedo uncia caterwaul lilac-point chocolate-point mackerel maltese knead whitenose vorpal}
    @catwords = @catadjs + @catnouns + @catmixed

    @jaegeradjs = %w{azure fearless lucky olive vivid electric grey yarely violet ivory jade cinnamon crimson tacit umber mammoth ultra iron zodiac}
    @jaegernouns = %w{horizon hulk ultimatum yardarm watchman whilrwind wright rhythm ocean enigma eruption typhoon jaeger brawler blaze vandal excalibur paladin juliet kaleidoscope romeo}
    @jaegermixed = %w{alpha ajax amber avenger brave bravo charlie chocolate chrome corinthian dancer danger dash delta duet echo edge elite eureka foxtrot guardian gold hyperion illusion imperative india intercept kilo lancer night nova november oscar omega pacer quickstrike rogue ronin striker tango titan valor victor vulcan warder xenomorph xenon xray xylem yankee yell yukon zeal zero zoner zodiac}
    @jaegerwords = @jaegeradjs + @jaegernouns + @jaegermixed

    @words = @catwords + @jaegerwords

  end #class
end #module

