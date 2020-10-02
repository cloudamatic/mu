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
require 'mu/mommacat/search'
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
        @chef_user = @mu_user.dup.delete(".")
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
      @original_config['environment'] ||= @environment if @original_config

      if set_context_to_me
        MU::MommaCat.setThreadContext(self)
      end

      if create and !@no_artifacts
        initDeployDirectory
        setDeploySecret
        MU::MommaCat.setThreadContext(self) if set_context_to_me
        save!
      end

      @appname ||= MU.appname
      @timestamp ||= MU.timestamp
      @environment ||= MU.environment

      loadDeploy(set_context_to_me: set_context_to_me)
      if !deploy_secret.nil? and !authKey(deploy_secret)
        raise DeployInitializeError, "Client request did not include a valid deploy authorization secret. Verify that userdata runs correctly?"
      end


      @@litter_semaphore.synchronize {
        @@litters[@deploy_id] ||= self
      }

      # Initialize a MU::Cloud object for each resource belonging to this
      # deploy, IF it already exists, which is to say if we're loading an
      # existing deploy instead of creating a new one.
      if !create and @deployment and @original_config and !skip_resource_objects
        loadObjects(delay_descriptor_load)
      end

      @initializing = false

# XXX this .owned? method may get changed by the Ruby maintainers
#     if !@@litter_semaphore.owned?
    end # end of initialize()

    # List all the cloud providers declared by resources in our deploy.
    def cloudsUsed
      seen = []
      seen << @original_config['cloud'] if @original_config['cloud']
      MU::Cloud.resource_types.each_value { |attrs|
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
      MU::Cloud.resource_types.each_value { |attrs|
        type = attrs[:cfg_plural]
        if @original_config[type]
          @original_config[type].each { |resource|
            if resource['credentials']
              seen << resource['credentials']
            else
              cloudconst = @original_config['cloud'] ? @original_config['cloud'] : MU::Config.defaultCloud
              seen << MU::Cloud.cloudClass(cloudconst).credConfig(name_only: true)
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

      MU::Cloud.resource_types.each_value { |attrs|
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
              # XXX this should be a general method implemented by each cloud
              # provider
              if resource['cloud'] == "Google"
                habitats << MU::Cloud.cloudClass(resource['cloud']).defaultProject(resource['credentials'])
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
              if MU::Cloud.resourceClass(resource['cloud'], res_type).isGlobal?
# XXX why was I doing this, urgh
                next
              elsif !resource['region']
                regions << MU::Cloud.cloudClass(resource['cloud']).myRegion(resource['credentials'])
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
      MU::Cloud.resource_types.each_value { |data|
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
        MU::Cloud.resource_types.each_value { |attrs|
          type = attrs[:cfg_plural]
          next if !@kittens.has_key?(type)
          tmplitter = @kittens[type].values.dup
          tmplitter.each { |nodeclass, data|
            if data.is_a?(Hash)
              data.each_key { |mu_name|
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
    def addKitten(type, name, object, do_notify: false)
      if !type or !name or !object or !object.mu_name
        raise MuError, "Nil arguments to addKitten are not allowed (got type: #{type}, name: #{name}, and '#{object}' to add)"
      end

      _shortclass, _cfg_name, type, _classname, attrs = MU::Cloud.getResourceNames(type)
      object.intoDeploy(self)

      add_block = Proc.new {
        @kittens[type] ||= {}
        @kittens[type][object.habitat] ||= {}
        if attrs[:has_multiples]
          @kittens[type][object.habitat][name] ||= {}
          @kittens[type][object.habitat][name][object.mu_name] = object
        else
          @kittens[type][object.habitat][name] = object
        end
        if do_notify
          notify(type, name, object.notify, triggering_node: object, delayed_save: true)
        end
      }

      begin
        @kitten_semaphore.synchronize {
          add_block.call()
        }
      rescue ThreadError => e
        # already locked by a parent call to this method, so this should be safe
        raise e if !e.message.match(/recursive locking/)
        add_block.call()
      end
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
          raise SecretError, "'#{type}' is not a valid secret type (valid types: #{@secrets.keys.join(", ")})"
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
          raise SecretError, "'#{type}' is not a valid secret type (valid types: #{@secrets.keys.join(", ")})"
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

    # Add or remove a resource's metadata to this deployment's structure and
    # flush it to disk.
    # @param type [String]: The type of resource (e.g. *server*, *database*).
    # @param key [String]: The name field of this resource.
    # @param mu_name [String]: The mu_name of this resource.
    # @param data [Hash]: The resource's metadata.
    # @param triggering_node [MU::Cloud]: A cloud object calling this notify, usually on behalf of itself
    # @param remove [Boolean]: Remove this resource from the deploy structure, instead of adding it.
    # @return [void]
    def notify(type, key, data, mu_name: nil, remove: false, triggering_node: nil, delayed_save: false)
      no_write = (@no_artifacts or caller.grep(/\/mommacat\.rb:\d+:in `notify'/))

      begin
        if !no_write
          if !MU::MommaCat.lock("deployment-notification", deploy_id: @deploy_id, retries: 10)
            raise MuError, "Failed to get deployment-notifcation lock for #{@deploy_id}"
          end
        end

        if !@need_deploy_flush or @deployment.nil? or @deployment.empty?
          loadDeploy(true) # make sure we're saving the latest and greatest
        end

        _shortclass, _cfg_name, type, _classname, attrs = MU::Cloud.getResourceNames(type, false)
        has_multiples = attrs[:has_multiples] ? true : false

        mu_name ||= if !data.nil? and !data["mu_name"].nil?
          data["mu_name"]
        elsif !triggering_node.nil? and !triggering_node.mu_name.nil?
          triggering_node.mu_name
        end
        if mu_name.nil? and has_multiples
          MU.log "MU::MommaCat.notify called to modify deployment struct for a type (#{type}) with :has_multiples, but no mu_name available to look under #{key}. Call was #{caller(1..1)}", MU::WARN, details: data
          return
        end

        @need_deploy_flush = true

        if !remove
          if data.nil?
            MU.log "MU::MommaCat.notify called to modify deployment struct, but no data provided", MU::WARN
            return
          end
          @notify_semaphore.synchronize {
            @deployment[type] ||= {}
          }
          if has_multiples
            @notify_semaphore.synchronize {
              @deployment[type][key] ||= {}
            }
            @deployment[type][key][mu_name] = data
            MU.log "Adding to @deployment[#{type}][#{key}][#{mu_name}]", MU::DEBUG, details: data
          else
            @deployment[type][key] = data
            MU.log "Adding to @deployment[#{type}][#{key}]", MU::DEBUG, details: data
          end
          if !delayed_save and !no_write
            save!(key)
          end
        else
          have_deploy = true
          if @deployment[type].nil? or @deployment[type][key].nil?
            MU.log "MU::MommaCat.notify called to remove #{type} #{key}#{has_multiples ? " "+mu_name : ""} deployment struct, but no such data exist", MU::DEBUG
            return
          end

          if have_deploy
            @notify_semaphore.synchronize {
              if has_multiples
                MU.log "Removing @deployment[#{type}][#{key}][#{mu_name}]", MU::DEBUG, details: @deployment[type][key][mu_name]
                @deployment[type][key].delete(mu_name)
              end

              if @deployment[type][key].empty? or !has_multiples
                MU.log "Removing @deployment[#{type}][#{key}]", MU::DEBUG, details: @deployment[type][key]
                @deployment[type].delete(key)
              end

              if @deployment[type].empty?
                @deployment.delete(type)
              end
            }
          end
          save! if !delayed_save and !no_write
        end
      ensure
        MU::MommaCat.unlock("deployment-notification", deploy_id: @deploy_id) if !no_write
      end
    end

    # Send a Slack notification to a deployment's administrators.
    # @param subject [String]: The subject line of the message.
    # @param msg [String]: The message body.
    # @return [void]
    def sendAdminSlack(subject, msg: "", scrub_mu_isms: true, snippets: [], noop: false)
      if MU.muCfg['slack'] and MU.muCfg['slack']['webhook'] and
         (!MU.muCfg['slack']['skip_environments'] or !MU.muCfg['slack']['skip_environments'].any?{ |s| s.casecmp(MU.environment)==0 })
        require 'slack-notifier'
        slackargs = nil
        keyword_args = { channel: MU.muCfg['slack']['channel'] }
        begin
          slack = Slack::Notifier.new MU.muCfg['slack']['webhook']
          prefix = scrub_mu_isms ? subject : "#{MU.appname} \*\"#{MU.handle}\"\* (`#{MU.deploy_id}`) - #{subject}"

          text = if msg and !msg.empty?
            "#{prefix}:\n\n```#{msg}```"
          else
            prefix
          end

          if snippets and snippets.size > 0
            keyword_args[:attachments] = snippets
          end

          if !noop
            slack.ping(text, **keyword_args)
          else
            MU.log "Would send to #{MU.muCfg['slack']['channel']}", MU::NOTICE, details: [ text, keyword_args ]
          end
        rescue Slack::Notifier::APIError => e
          MU.log "Failed to send message to slack: #{e.message}", MU::ERR, details: keyword_args
          return false
        end
      end
      true
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
      message = <<MAIL_HEAD_END
From: #{MU.handle} <root@localhost>
To: #{to.join(",")}
Subject: #{subject}

      #{msg}
MAIL_HEAD_END
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

      siblings = findLitterMate(type: "server", return_all: true)
      return if siblings.nil? or (siblings.respond_to?(:empty?) and siblings.empty?)

      update_servers = []
      siblings.each_pair { |mu_name, node|
        next if mu_name == triggering_node or node.groomer.nil?
        next if nodeclasses.size > 0 and !nodeclasses.include?(node.config['name'])
        if !node.deploydata or !node.deploydata['nodename']
          MU.log "#{mu_name} deploy data is missing (possibly retired or mid-bootstrap), so not syncing it", MU::NOTICE
          next
        end

        if @deployment["servers"][node.config['name']][node.mu_name].nil? or
           @deployment["servers"][node.config['name']][node.mu_name] != node.deploydata
          @deployment["servers"][node.config['name']][node.mu_name] = node.deploydata
        elsif !save_only
          # Don't bother running grooms on nodes that don't need to be updated,
          # unless we're just going to do a save.
          next
        end
        update_servers << node
      }

      return if update_servers.empty?

      MU.log "Updating nodes in #{@deploy_id}", MU::DEBUG, details: update_servers.map { |n| n.mu_name }

      threads = []
      update_servers.each { |sibling|
        next if sibling.config.has_key?("groom") and !sibling.config["groom"]
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
          cloudclass = MU::Cloud.cloudClass(resource.config['cloud'])

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
