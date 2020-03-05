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
require 'mu/mommacat/storage'
require 'mu/mommacat/daemon'
require 'mu/mommacat/naming'

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
    @@litters_loadtime = {}
    @@litter_semaphore = Mutex.new

    # Update the in-memory cache of a given deploy. This is intended for use by
    # {#save!}, primarily.
    # @param deploy_id [String]
    # @param litter [MU::MommaCat]
    def self.updateLitter(deploy_id, litter)
      return if litter.nil?
      @@litter_semaphore.synchronize {
        @@litters[deploy_id] = litter
        @@litters_loadtime[deploy_id] = Time.now
      }
    end

    attr_reader :initializing
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
    @nocleanup = false

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
                   appname: nil,
                   timestamp: nil,
                   set_context_to_me: true,
                   skip_resource_objects: false,
                   no_artifacts: false,
                   deployment_data: {},
                   delay_descriptor_load: false,
                   mu_user: Etc.getpwuid(Process.uid).name
    )
      if deploy_id.nil? or deploy_id.empty?
        raise DeployInitializeError, "MommaCat objects must specify a deploy_id"
      end
      set_context_to_me = true if create
      @initializing = true

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
      @original_config = MU::Config.manxify(config)
      @nocleanup = nocleanup
      @secret_semaphore = Mutex.new
      @notify_semaphore = Mutex.new
      @need_deploy_flush = false
      @node_cert_semaphore = Mutex.new
      @deployment = deployment_data
      @deployment['mu_public_ip'] = MU.mu_public_ip
      @private_key = nil
      @public_key = nil
      @secrets = Hash.new
      @secrets['instance_secret'] = Hash.new
      @ssh_key_name = ssh_key_name
      @ssh_private_key = ssh_private_key
      @ssh_public_key = ssh_public_key
      @clouds = {}
      @seed = MU.seed # pass this in
      @handle = MU.handle # pass this in
      @appname = appname
      @appname ||= @original_config['name'] if @original_config
      @timestamp = timestamp
      @environment = environment

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

        MU::Cloud.resource_types.values.each { |attrs|
          if !@original_config[attrs[:cfg_plural]].nil? and @original_config[attrs[:cfg_plural]].size > 0
            @original_config[attrs[:cfg_plural]].each { |resource|

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
        if !@original_config['scrub_mu_isms'] and !@no_artifacts
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

      @appname ||= MU.appname
      @timestamp ||= MU.timestamp
      @environment ||= MU.environment

      loadDeploy(set_context_to_me: set_context_to_me)
      if !deploy_secret.nil?
        if !authKey(deploy_secret)
          raise DeployInitializeError, "Client request did not include a valid deploy authorization secret. Verify that userdata runs correctly?"
        end
      end


      @@litter_semaphore.synchronize {
        @@litters[@deploy_id] ||= self
      }

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

              if orig_cfg['vpc'] and orig_cfg['vpc'].is_a?(Hash)
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
                # Load up MU::Cloud objects for all our kittens in this deploy
                orig_cfg['environment'] = @environment # not always set in old deploys
                if attrs[:has_multiples]
                  data.keys.each { |mu_name|
                    attrs[:interface].new(mommacat: self, kitten_cfg: orig_cfg, mu_name: mu_name, delay_descriptor_load: delay_descriptor_load)
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
              rescue StandardError => e
                if e.class != MU::Cloud::MuCloudResourceNotImplemented
                  MU.log "Failed to load an existing resource of type '#{type}' in #{@deploy_id}: #{e.inspect}", MU::WARN, details: e.backtrace
                end
              end
            }

          end
        }
      end

      @initializing = false

# XXX this .owned? method may get changed by the Ruby maintainers
#     if !@@litter_semaphore.owned?
    end # end of initialize()

    # List all the cloud providers declared by resources in our deploy.
    def cloudsUsed
      seen = []
      seen << @original_config['cloud'] if @original_config['cloud']
      MU::Cloud.resource_types.values.each { |attrs|
        type = attrs[:cfg_plural]
        if @original_config[type]
          @original_config[type].each { |resource|
            seen << resource['cloud'] if resource['cloud']
          }
        end
      }
      seen.uniq
    end

    # Assay this deployment for a list of credentials (from mu.yaml) which are
    # used. Our Cleanup module can leverage this to skip unnecessary checks.
    # @return [Array<String>]
    def credsUsed
      return [] if !@original_config
      seen = []
#      clouds = []
      seen << @original_config['credentials'] if @original_config['credentials']
#      defaultcloud = @original_config['cloud']
      MU::Cloud.resource_types.values.each { |attrs|
        type = attrs[:cfg_plural]
        if @original_config[type]
          @original_config[type].each { |resource|
            if resource['credentials']
              seen << resource['credentials']
            else
              cloudclass = if @original_config['cloud']
                Object.const_get("MU").const_get("Cloud").const_get(@original_config['cloud'])
              else
                Object.const_get("MU").const_get("Cloud").const_get(MU::Config.defaultCloud)
              end
              seen << cloudclass.credConfig(name_only: true)
            end
          }
        end
      }
# XXX insert default for each cloud provider if not explicitly seen
      seen.uniq
    end

    # List the accounts/projects/subscriptions used by each resource in our
    # deploy.
    # @return [Array<String>]
    def habitatsUsed
      return [] if !@original_config
      habitats = []
      habitats << @original_config['project'] if @original_config['project']
      if @original_config['habitat']
        hab_ref = MU::Config::Ref.get(@original_config['habitat'])
        if hab_ref and hab_ref.id
          habitats << hab_ref.id
        end
      end

      MU::Cloud.resource_types.values.each { |attrs|
        type = attrs[:cfg_plural]
        if @original_config[type]
          @original_config[type].each { |resource|
            if resource['project']
              habitats << resource['project']
            elsif resource['habitat']
              hab_ref = MU::Config::Ref.get(resource['habitat'])
              if hab_ref and hab_ref.id
                habitats << hab_ref.id
              end
            elsif resource['cloud']
              cloudclass = Object.const_get("MU").const_get("Cloud").const_get(resource['cloud'])
              # XXX this should be a general method implemented by each cloud
              # provider
              if resource['cloud'] == "Google"
                habitats << cloudclass.defaultProject(resource['credentials'])
              end
            end
          }
        end
      }

      habitats.uniq!
    end

    # List the regions used by each resource in our deploy. This will just be
    # a flat list of strings with no regard to which region belongs with what
    # cloud provider- things mostly use this as a lookup table so they can
    # safely skip unnecessary regions when creating/cleaning deploy artifacts.
    # @return [Array<String>]
    def regionsUsed
      return [] if !@original_config
      regions = []
      regions << @original_config['region'] if @original_config['region']
      MU::Cloud.resource_types.each_pair { |res_type, attrs|
        type = attrs[:cfg_plural]
        if @original_config[type]
          @original_config[type].each { |resource|
            if resource['cloud']
              cloudclass = Object.const_get("MU").const_get("Cloud").const_get(resource['cloud'])
              resclass = Object.const_get("MU").const_get("Cloud").const_get(resource['cloud']).const_get(res_type.to_s)
              if resclass.isGlobal?
# XXX why was I doing this, urgh
                next
              elsif !resource['region']
                regions << cloudclass.myRegion
              end
            end
            if resource['region']
              regions << resource['region'] if resource['region']
            else
            end
          }
        end
      }

      regions.uniq
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
          cfg_plural = MU::Cloud.getResourceNames(type)[2]
          realtypes << cfg_plural
        }
      end

      count = 0
      MU::Cloud.resource_types.values.each { |data|
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
        MU::Cloud.resource_types.values.each { |attrs|
          type = attrs[:cfg_plural]
          next if !@kittens.has_key?(type)
          tmplitter = @kittens[type].values.dup
          tmplitter.each { |nodeclass, data|
            if data.is_a?(Hash)
              data.keys.each { |mu_name|
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

    # Keep tabs on a {MU::Cloud} object so that it can be found easily by
    # #findLitterMate.
    # @param type [String]:
    # @param name [String]:
    # @param object [MU::Cloud]:
    def addKitten(type, name, object)
      if !type or !name or !object or !object.mu_name
        raise MuError, "Nil arguments to addKitten are not allowed (got type: #{type}, name: #{name}, and '#{object}' to add)"
      end

      _shortclass, _cfg_name, type, _classname, attrs = MU::Cloud.getResourceNames(type)
      has_multiples = attrs[:has_multiples]
      object.intoDeploy(self)

      @kitten_semaphore.synchronize {
        @kittens[type] ||= {}
        @kittens[type][object.habitat] ||= {}
        if has_multiples
          @kittens[type][object.habitat][name] ||= {}
          @kittens[type][object.habitat][name][object.mu_name] = object
        else
          @kittens[type][object.habitat][name] = object
        end
      }
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
        raise SecretError, "saveNodeSecret requires instance_id (#{instance_id}), raw_secret (#{raw_secret}), and type (#{type}) args"
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
          FileUtils.chown Etc.getpwnam(@mu_user).uid, Etc.getpwnam(@mu_user).gid, ssh_dir
        end
      end
      if !File.exist?("#{ssh_dir}/#{@ssh_key_name}")
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
            next if descriptor['cloud'] != "AWS"
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

    @@dummy_cache = {}

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
    def self.findStray(
        cloud,
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
        habitats: [],
        dummy_ok: false,
        debug: false,
        no_deploy_search: false
    ) 
      start = Time.now
      callstr = "findStray(cloud: #{cloud}, type: #{type}, deploy_id: #{deploy_id}, calling_deploy: #{calling_deploy.deploy_id if !calling_deploy.nil?}, name: #{name}, cloud_id: #{cloud_id}, tag_key: #{tag_key}, tag_value: #{tag_value}, credentials: #{credentials}, habitats: #{habitats ? habitats.to_s : "[]"}, dummy_ok: #{dummy_ok.to_s}, flags: #{flags.to_s}) from #{caller[0]}"
#      callstack = caller.dup

      return nil if cloud == "CloudFormation" and !cloud_id.nil?
      shortclass, _cfg_name, cfg_plural, classname, _attrs = MU::Cloud.getResourceNames(type)
      if !MU::Cloud.supportedClouds.include?(cloud) or shortclass.nil?
        MU.log "findStray was called with bogus cloud argument '#{cloud}'", MU::WARN, details: callstr
        return nil
      end

      begin
        # TODO this is dumb as hell, clean this up.. and while we're at it
        # .dup everything so we don't mangle referenced values from the caller
        deploy_id = deploy_id.to_s if deploy_id.class.to_s == "MU::Config::Tail"
        name = name.to_s if name.class.to_s == "MU::Config::Tail"
        cloud_id = cloud_id.to_s if !cloud_id.nil?
        mu_name = mu_name.to_s if mu_name.class.to_s == "MU::Config::Tail"
        tag_key = tag_key.to_s if tag_key.class.to_s == "MU::Config::Tail"
        tag_value = tag_value.to_s if tag_value.class.to_s == "MU::Config::Tail"
        type = cfg_plural
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

        MU.log callstr, loglevel, details: caller

        # See if the thing we're looking for is a member of the deploy that's
        # asking after it.
        if !deploy_id.nil? and !calling_deploy.nil? and
            calling_deploy.deploy_id == deploy_id and (!name.nil? or !mu_name.nil?)
          handle = calling_deploy.findLitterMate(type: type, name: name, mu_name: mu_name, cloud_id: cloud_id, credentials: credentials)
          return [handle] if !handle.nil?
        end

        kittens = {}
        # Search our other deploys for matching resources
        if !no_deploy_search and (deploy_id or name or mu_name or cloud_id)
          MU.log "findStray: searching my deployments (#{cfg_plural}, name: #{name}, deploy_id: #{deploy_id}, mu_name: #{mu_name}) - #{sprintf("%.2fs", (Time.now-start))}", loglevel

          # Check our in-memory cache of live deploys before resorting to
          # metadata
          littercache = nil
          # Sometimes we're called inside a locked thread, sometimes not. Deal
          # with locking gracefully.
          begin
            @@litter_semaphore.synchronize {
              littercache = @@litters.dup
            }
          rescue ThreadError => e
            raise e if !e.message.match(/recursive locking/)
            littercache = @@litters.dup
          end

          littercache.each_pair { |cur_deploy, momma|
            next if deploy_id and deploy_id != cur_deploy
            
            straykitten = momma.findLitterMate(type: type, cloud_id: cloud_id, name: name, mu_name: mu_name, credentials: credentials, created_only: true)
            if straykitten
              MU.log "Found matching kitten #{straykitten.mu_name} in-memory - #{sprintf("%.2fs", (Time.now-start))}", loglevel
              # Peace out if we found the exact resource we want
              if cloud_id and straykitten.cloud_id.to_s == cloud_id.to_s
                return [straykitten]
              elsif mu_name and straykitten.mu_name == mu_name
                return [straykitten]
              else
                kittens[straykitten.cloud_id] ||= straykitten
              end
            end
          }

          mu_descs = MU::MommaCat.getResourceMetadata(cfg_plural, name: name, deploy_id: deploy_id, mu_name: mu_name)
          MU.log "findStray: #{mu_descs.size.to_s} deploys had matches - #{sprintf("%.2fs", (Time.now-start))}", loglevel

          mu_descs.each_pair { |cur_deploy_id, matches|
            MU.log "findStray: #{cur_deploy_id} had #{matches.size.to_s} initial matches - #{sprintf("%.2fs", (Time.now-start))}", loglevel
            next if matches.nil? or matches.size == 0

            momma = MU::MommaCat.getLitter(cur_deploy_id)

            straykitten = nil

            # If we found exactly one match in this deploy, use its metadata to
            # guess at resource names we weren't told.
            if matches.size > 1 and cloud_id
              MU.log "findStray: attempting to narrow down multiple matches with cloud_id #{cloud_id} - #{sprintf("%.2fs", (Time.now-start))}", loglevel
              straykitten = momma.findLitterMate(type: type, cloud_id: cloud_id, credentials: credentials, created_only: true)
            elsif matches.size == 1 and name.nil? and mu_name.nil?
              if cloud_id.nil?
                straykitten = momma.findLitterMate(type: type, name: matches.first["name"], cloud_id: matches.first["cloud_id"], credentials: credentials)
              else
                MU.log "findStray: fetching single match with cloud_id #{cloud_id} - #{sprintf("%.2fs", (Time.now-start))}", loglevel
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
            straykitten.intoDeploy(momma)

            if straykitten.cloud_id.nil?
              MU.log "findStray: kitten #{straykitten.mu_name} came back with nil cloud_id", MU::WARN
              next
            end

            kittens[straykitten.cloud_id] ||= straykitten

            # Peace out if we found the exact resource we want
            if cloud_id and straykitten.cloud_id.to_s == cloud_id.to_s
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
          if cloud_id or (tag_key and tag_value) or !flags.empty? or allow_multi

            regions = begin
              region ? [region] : cloudclass.listRegions(credentials: creds)
            rescue NoMethodError # Not all cloud providers have regions
              [nil]
            end

            # ..not all resource types care about regions either
            if resourceclass.isGlobal?
              regions = [nil]
            end

            # Decide what habitats (accounts/projects/subscriptions) we'll
            # search, if applicable for this resource type.
            habitats ||= []
            begin
              if flags["project"] # backwards-compat
                habitats << flags["project"]
              end
              if habitats.empty?
                if resourceclass.canLiveIn.include?(nil)
                  habitats << nil
                end
                if resourceclass.canLiveIn.include?(:Habitat)
                  habitats.concat(cloudclass.listProjects(creds))
                end
              end
            rescue NoMethodError # we only expect this to work on Google atm
            end

            if habitats.empty?
              habitats << nil
            end
            habitats.uniq!

            habitat_threads = []
            desc_semaphore = Mutex.new

            cloud_descs = {}
            habitats.each { |hab|
              begin
                habitat_threads.each { |t| t.join(0.1) }
                habitat_threads.reject! { |t| t.nil? or !t.status }
                sleep 1 if habitat_threads.size > 5
              end while habitat_threads.size > 5
              habitat_threads << Thread.new(hab) { |p|
                MU.log "findStray: Searching #{p} (#{habitat_threads.size.to_s} habitat threads running) - #{sprintf("%.2fs", (Time.now-start))}", loglevel
                cloud_descs[p] = {}
                region_threads = []
                regions.each { |reg| region_threads << Thread.new(reg) { |r|
                  MU.log "findStray: Searching #{r} in #{p} (#{region_threads.size.to_s} region threads running) - #{sprintf("%.2fs", (Time.now-start))}", loglevel
                  MU.log "findStray: calling #{classname}.find(cloud_id: #{cloud_id}, region: #{r}, tag_key: #{tag_key}, tag_value: #{tag_value}, flags: #{flags}, credentials: #{creds}, project: #{p}) - #{sprintf("%.2fs", (Time.now-start))}", loglevel
                  found = resourceclass.find(cloud_id: cloud_id, region: r, tag_key: tag_key, tag_value: tag_value, flags: flags, credentials: creds, habitat: p)
                  MU.log "findStray: #{found ? found.size.to_s : "nil"} results - #{sprintf("%.2fs", (Time.now-start))}", loglevel

                  if found
                    desc_semaphore.synchronize {
                      cloud_descs[p][r] = found
                    }
                  end
                  # Stop if you found the thing by a specific cloud_id
                  if cloud_id and found and !found.empty?
                    found_the_thing = true
                    Thread.exit
                  end
                } }
                begin
                  region_threads.each { |t| t.join(0.1) }
                  region_threads.reject! { |t| t.nil? or !t.status }
                  if region_threads.size > 0
                    MU.log "#{region_threads.size.to_s} regions still running in #{p}", loglevel
                    sleep 3
                  end
                end while region_threads.size > 0
              }
            }
            begin
              habitat_threads.each { |t| t.join(0.1) }
              habitat_threads.reject! { |t| t.nil? or !t.status }
              if habitat_threads.size > 0
                MU.log "#{habitat_threads.size.to_s} habitats still running", loglevel
                sleep 3
              end
            end while habitat_threads.size > 0

            habitat_threads = []
            habitats.each { |hab| habitat_threads << Thread.new(hab) { |p|
              region_threads = []
              regions.each { |reg| region_threads << Thread.new(reg) { |r|
                next if cloud_descs[p][r].nil?
                cloud_descs[p][r].each_pair { |kitten_cloud_id, descriptor|

                  # We already have a MU::Cloud object for this guy, use it
                  if kittens.has_key?(kitten_cloud_id)
                    desc_semaphore.synchronize {
                      matches << kittens[kitten_cloud_id]
                    }
                  elsif kittens.size == 0
                    if !dummy_ok
                      next
                    end

                    # If we don't have a MU::Cloud object, manufacture a dummy
                    # one.  Give it a fake name if we have to and have decided
                    # that's ok. Wild inferences from the cloud descriptor are
                    # ok to try here.
                    use_name = if (name.nil? or name.empty?)
                      if !dummy_ok
                        nil
                      elsif !mu_name.nil?
                        mu_name
                      # AWS-style tags
                      elsif descriptor.respond_to?(:tags) and
                            descriptor.tags.is_a?(Array) and
                            descriptor.tags.first.respond_to?(:key) and
                            descriptor.tags.map { |t| t.key }.include?("Name")
                        descriptor.tags.select { |t| t.key == "Name" }.first.value
                      else
                        try = nil
                        # Various GCP fields
                        [:display_name, :name, (resourceclass.cfg_name+"_name").to_sym].each { |field|
                          if descriptor.respond_to?(field) and descriptor.send(field).is_a?(String)
                            try = descriptor.send(field)
                            break
                          end

                        }
                        try ||= if !tag_value.nil?
                            tag_value
                          else
                            kitten_cloud_id
                          end
                        try
                      end
                    else
                      name
                    end
                    if use_name.nil?
                      MU.log "Found cloud provider data for #{cloud} #{type} #{kitten_cloud_id}, but without a name I can't manufacture a proper #{type} object to return - #{sprintf("%.2fs", (Time.now-start))}", loglevel, details: caller
                      next
                    end
                    cfg = {
                      "name" => use_name,
                      "cloud" => cloud,
                      "credentials" => creds
                    }
                    if !r.nil? and !resourceclass.isGlobal?
                     cfg["region"] = r
                    end

                    if !p.nil? and resourceclass.canLiveIn.include?(:Habitat)
                      cfg["project"] = p
                    end
                    # If we can at least find the config from the deploy this will
                    # belong with, use that, even if it's an ungroomed resource.
                    if !calling_deploy.nil? and
                       !calling_deploy.original_config.nil? and
                       !calling_deploy.original_config[type+"s"].nil?
                      calling_deploy.original_config[type+"s"].each { |s|
                        if s["name"] == use_name
                          cfg = s.dup
                          break
                        end
                      }

                      newkitten = resourceclass.new(mommacat: calling_deploy, kitten_cfg: cfg, cloud_id: kitten_cloud_id)
                      desc_semaphore.synchronize {
                        matches << newkitten
                      }
                    else
                      if !@@dummy_cache[cfg_plural] or !@@dummy_cache[cfg_plural][cfg.to_s]
                        MU.log "findStray: Generating dummy '#{resourceclass.to_s}' cloudobj with name: #{use_name}, cloud_id: #{kitten_cloud_id.to_s} - #{sprintf("%.2fs", (Time.now-start))}", loglevel, details: cfg
                        resourceclass.new(mu_name: use_name, kitten_cfg: cfg, cloud_id: kitten_cloud_id.to_s, from_cloud_desc: descriptor)
                        desc_semaphore.synchronize {
                          @@dummy_cache[cfg_plural] ||= {}
                          @@dummy_cache[cfg_plural][cfg.to_s] = resourceclass.new(mu_name: use_name, kitten_cfg: cfg, cloud_id: kitten_cloud_id.to_s, from_cloud_desc: descriptor)
                          MU.log "findStray: Finished generating dummy '#{resourceclass.to_s}' cloudobj - #{sprintf("%.2fs", (Time.now-start))}", loglevel
                        }
                      end
                      desc_semaphore.synchronize {
                        matches << @@dummy_cache[cfg_plural][cfg.to_s]
                      }
                    end
                  end
                }
              } }
              MU.log "findStray: tying up #{region_threads.size.to_s} region threads - #{sprintf("%.2fs", (Time.now-start))}", loglevel
              region_threads.each { |t|
                t.join
              }
            } }
            MU.log "findStray: tying up #{habitat_threads.size.to_s} habitat threads - #{sprintf("%.2fs", (Time.now-start))}", loglevel
            habitat_threads.each { |t|
              t.join
            }
          end
        }
      rescue StandardError => e
        MU.log e.inspect, MU::ERR, details: e.backtrace
      end
      MU.log "findStray: returning #{matches ? matches.size.to_s : "0"} matches - #{sprintf("%.2fs", (Time.now-start))}", loglevel

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
    def findLitterMate(type: nil, name: nil, mu_name: nil, cloud_id: nil, created_only: false, return_all: false, credentials: nil, habitat: nil, debug: false, indent: "")
      shortclass, cfg_name, cfg_plural, classname, attrs = MU::Cloud.getResourceNames(type)
      type = cfg_plural
      has_multiples = attrs[:has_multiples]

      loglevel = debug ? MU::NOTICE : MU::DEBUG

      argstring = [:type, :name, :mu_name, :cloud_id, :created_only, :credentials, :habitat, :has_multiples].reject { |a|
        binding.local_variable_get(a).nil?
      }.map { |v|
        v.to_s+": "+binding.local_variable_get(v).to_s
      }.join(", ")

      # Fun times: if we specified a habitat, which we may also have done by
      # its shorthand sibling name, let's... call ourselves first to make sure
      # we're fishing for the right thing.
      if habitat
        if habitat.is_a?(MU::Config::Ref) and habitat.id
          habitat = habitat.id
        else
          MU.log indent+"findLitterMate(#{argstring}): Attempting to resolve habitat name #{habitat}", loglevel
          realhabitat = findLitterMate(type: "habitat", name: habitat, debug: debug, credentials: credentials, indent: indent+"  ")
          if realhabitat and realhabitat.mu_name
            MU.log indent+"findLitterMate: Resolved habitat name #{habitat} to #{realhabitat.mu_name}", loglevel, details: [realhabitat.mu_name, realhabitat.cloud_id, realhabitat.config.keys]
            habitat = realhabitat.cloud_id
          elsif debug
            MU.log indent+"findLitterMate(#{argstring}): Failed to resolve habitat name #{habitat}", MU::WARN
          end
        end
      end


      @kitten_semaphore.synchronize {
        if !@kittens.has_key?(type)
          if debug
            MU.log indent+"NO SUCH KEY #{type} findLitterMate(#{argstring})", MU::WARN, details: @kittens.keys
          end
          return nil
        end
        MU.log indent+"START findLitterMate(#{argstring}), caller: #{caller[2]}", loglevel, details: @kittens[type].keys.map { |hab| hab.to_s+": "+@kittens[type][hab].keys.join(", ") }
        matches = []

        @kittens[type].each { |habitat_group, sib_classes|
          next if habitat and habitat_group != habitat and !habitat_group.nil?
          sib_classes.each_pair { |sib_class, data|
          virtual_name = nil

          if !has_multiples and data and !data.is_a?(Hash) and data.config and data.config.is_a?(Hash) and data.config['virtual_name'] and name == data.config['virtual_name']
            virtual_name = data.config['virtual_name']
          elsif !name.nil? and name != sib_class
            next
          end
          if has_multiples
            if !name.nil?
              if return_all
                MU.log indent+"MULTI-MATCH RETURN_ALL findLitterMate(#{argstring})", loglevel, details: data.keys
                return data.dup
              end
              if data.size == 1 and (cloud_id.nil? or data.values.first.cloud_id == cloud_id)
                return data.values.first
              elsif mu_name.nil? and cloud_id.nil?
                MU.log indent+"#{@deploy_id}: Found multiple matches in findLitterMate based on #{type}: #{name}, and not enough info to narrow down further. Returning an arbitrary result. Caller: #{caller[2]}", MU::WARN, details: data.keys
                return data.values.first
              end
            end
            data.each_pair { |sib_mu_name, obj|
              if (!mu_name.nil? and mu_name == sib_mu_name) or
                  (!cloud_id.nil? and cloud_id == obj.cloud_id) or
                  (!credentials.nil? and credentials == obj.credentials)
                if !created_only or !obj.cloud_id.nil?
                  if return_all
                    MU.log indent+"MULTI-MATCH RETURN_ALL findLitterMate(#{argstring})", loglevel, details: data.keys
                    return data.dup
                  else
                    MU.log indent+"MULTI-MATCH findLitterMate(#{argstring})", loglevel, details: data.keys
                    return obj
                  end
                end
              end
            }
          else

            MU.log indent+"CHECKING AGAINST findLitterMate #{habitat_group}/#{type}/#{sib_class} data.cloud_id: #{data.cloud_id}, data.credentials: #{data.credentials}, sib_class: #{sib_class}, virtual_name: #{virtual_name}", loglevel, details: argstring

            data_cloud_id = data.cloud_id.nil? ? nil : data.cloud_id.to_s

            MU.log indent+"(name.nil? or sib_class == name or virtual_name == name)", loglevel, details: (name.nil? or sib_class == name or virtual_name == name).to_s
            MU.log indent+"(cloud_id.nil? or cloud_id[#{cloud_id.class.name}:#{cloud_id.to_s}] == data_cloud_id[#{data_cloud_id.class.name}:#{data_cloud_id}])", loglevel, details: (cloud_id.nil? or cloud_id == data_cloud_id).to_s
            MU.log indent+"(credentials.nil? or data.credentials.nil? or credentials[#{credentials.class.name}:#{credentials}] == data.credentials[#{data.credentials.class.name}:#{data.credentials}])", loglevel, details: (credentials.nil? or data.credentials.nil? or credentials == data.credentials).to_s

            if (name.nil? or sib_class == name.to_s or virtual_name == name.to_s) and
                (cloud_id.nil? or cloud_id.to_s == data_cloud_id) and
                (credentials.nil? or data.credentials.nil? or credentials.to_s == data.credentials.to_s)
              MU.log indent+"OUTER MATCH PASSED, NEED !created_only (#{created_only.to_s}) or !data_cloud_id.nil? (#{data_cloud_id})", loglevel, details: (cloud_id.nil? or cloud_id == data_cloud_id).to_s
              if !created_only or !data_cloud_id.nil?
                MU.log indent+"SINGLE MATCH findLitterMate(#{argstring})", loglevel, details: [data.mu_name, data_cloud_id, data.config.keys]
                matches << data
              end
            end
          end
          }
        }

        return matches.first if matches.size == 1
        if return_all and matches.size > 1
          return matches
        end
      }

      MU.log indent+"NO MATCH findLitterMate(#{argstring})", loglevel

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

      if !@need_deploy_flush or @deployment.nil? or @deployment.empty?
        loadDeploy(true) # make sure we're saving the latest and greatest
      end

      _shortclass, _cfg_name, cfg_plural, _classname, attrs = MU::Cloud.getResourceNames(type)
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

      @need_deploy_flush = true

      if !remove
        if data.nil?
          MU.log "MU::MommaCat.notify called to modify deployment struct, but no data provided", MU::WARN
          MU::MommaCat.unlock("deployment-notification")
          return
        end
        @notify_semaphore.synchronize {
          @deployment[type] ||= {}
        }
        if has_multiples
          @notify_semaphore.synchronize {
            @deployment[type][key] ||= {}
          }
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
          @notify_semaphore.synchronize {
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
          }
        end
        save! if !delayed_save

      end

      MU::MommaCat.unlock("deployment-notification")
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
    def sendAdminMail(subject, msg: "", kitten: nil, data: nil, debug: false)
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

    # Make sure deployment data is synchronized to/from each +Server+ in the
    # currently-loaded deployment.
    # @param nodeclasses [Array<String>]
    # @param triggering_node [String,MU::Cloud::Server]
    # @param save_only [Boolean]
    def syncLitter(nodeclasses = [], triggering_node: nil, save_only: false)
      return if MU.syncLitterThread # don't run recursively by accident
      return if !Dir.exist?(deploy_dir)

      if !triggering_node.nil? and triggering_node.is_a?(MU::Cloud::Server)
        triggering_node = triggering_node.mu_name
      end

      litter = findLitterMate(type: "server", return_all: true)
      return if litter.nil? or litter.empty?

      update_servers = []
      litter.each_pair { |mu_name, node|
        next if mu_name == triggering_node or node.groomer.nil?
        next if nodeclasses.size > 0 and !nodeclasses.include?(node.config['name'])
        if !node.deploydata or !node.deploydata.keys.include?('nodename')
          MU.log "#{mu_name} deploy data is missing (possibly retired or mid-bootstrap), so not syncing it", MU::NOTICE, details: node.deploydata ? node.deploydata.keys : nil
          next
        end
        update_servers << node
      }

      # If we're going to be invoking grooms on things, make sure everyone's
      # deploydata together, and take node of nodes which don't need an update.
      if !save_only
        skip = []
        update_servers.each { |node|

          if @deployment["servers"][node.config['name']][node.mu_name].nil? or
             @deployment["servers"][node.config['name']][node.mu_name] != node.deploydata
            @deployment["servers"][node.config['name']][node.mu_name] = node.deploydata
          else
            skip << node
          end
        }
        update_servers = update_servers - skip
      end

      return if update_servers.empty?

      MU.log "Updating nodes in #{@deploy_id}", MU::DEBUG, details: update_servers.map { |n| n.mu_name }

      threads = []
      update_servers.each { |sibling|
        next if sibling.config['groom'].nil? or sibling.config['groom']
        threads << Thread.new {
          Thread.abort_on_exception = true
          Thread.current.thread_variable_set("name", "sync-"+sibling.mu_name.downcase)
          MU.setVar("syncLitterThread", true)
          begin
            sibling.groomer.saveDeployData
            sibling.groomer.run(purpose: "Synchronizing sibling kittens") if !save_only
          rescue MU::Groomer::RunError => e
            MU.log "Sync of #{sibling.mu_name} failed", MU::WARN, details: e.inspect
          end
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
      _nat_ssh_key, _nat_ssh_user, _nat_ssh_host, canonical_ip, _ssh_user, _ssh_key_name = resource.getSSHConfig if resource.respond_to?(:getSSHConfig)

      deploy_id = resource.deploy_id || @deploy_id || resource.deploy.deploy_id

      cert_cn = poolname ? deploy_id + "-" + resource.config['name'].upcase : resource.mu_name

      results = {}

      is_windows = (resource.respond_to?(:windows?) and resource.windows?)

      @node_cert_semaphore.synchronize {
        MU::Master::SSL.bootstrap
        sans = []
        sans << canonical_ip if canonical_ip
        sans << resource.mu_name.downcase if resource.mu_name and resource.mu_name != cert_cn
        # XXX were there other names we wanted to include?
        key = MU::Master::SSL.getKey(cert_cn, keysize: keysize)
        cert, pfx_cert = MU::Master::SSL.getCert(cert_cn, "/CN=#{cert_cn}/O=Mu/C=US", sans: sans, pfx: is_windows)
        results[cert_cn] = [key, cert]

        winrm_cert = nil
        if is_windows
          winrm_key = MU::Master::SSL.getKey(cert_cn+"-winrm", keysize: keysize)
          winrm_cert = MU::Master::SSL.getCert(cert_cn+"-winrm", "/CN=#{resource.config['windows_admin_username']}/O=Mu/C=US", sans: ["otherName:1.3.6.1.4.1.311.20.2.3;UTF8:#{resource.config['windows_admin_username']}@localhost"], pfx: true)[0]
          results[cert_cn+"-winrm"] = [winrm_key, winrm_cert]
        end

        if resource and resource.config and resource.config['cloud']
          cloudclass = Object.const_get("MU").const_get("Cloud").const_get(resource.config['cloud'])

          cloudclass.writeDeploySecret(@deploy_id, cert.to_pem, cert_cn+".crt", credentials: resource.config['credentials'])
          cloudclass.writeDeploySecret(@deploy_id, key.to_pem, cert_cn+".key", credentials: resource.config['credentials'])
          if pfx_cert
            cloudclass.writeDeploySecret(@deploy_id, pfx_cert.to_der, cert_cn+".pfx", credentials: resource.config['credentials'])
          end
          if winrm_cert
            cloudclass.writeDeploySecret(@deploy_id, winrm_cert.to_pem, cert_cn+"-winrm.crt", credentials: resource.config['credentials'])
          end
        end

      }

      results[cert_cn]
    end

    private

    def createDeployKey
      key = OpenSSL::PKey::RSA.generate(4096)
      MU.log "Generated deploy key for #{MU.deploy_id}", MU::DEBUG, details: key.public_key.export
      return [key.export, key.public_key.export]
    end

    ###########################################################################
    ###########################################################################
    def setThreadContextToMe
      ["appname", "environment", "timestamp", "seed", "handle"].each { |var|
        @deployment[var] ||= instance_variable_get("@#{var}".to_sym)
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

  end #class
end #module
