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

#require 'thin'
#require 'rack'
autoload :Net, 'net/ssh'
require 'fileutils'
require 'json'
require 'stringio'
require 'securerandom'
gem "chef"
autoload :Chef, 'chef'
gem "chef-vault"
autoload :ChefVault, 'chef-vault'
gem "knife-windows"

module MU

	# MommaCat is in charge of managing metadata about resources we've created,
	# as well as orchestrating amongst them and bootstrapping nodes outside of
	# the normal synchronous deploy sequence invoked by *mu-deploy*.
	class MommaCat

		# An exception denoting a failure in MommaCat#fetchSecret and related methods
		class SecretError < MuError; end

		# Failure to load or create a deploy
		class DeployInitializeError < MuError; end

		# Failure to groom a node
		class GroomError < MuError; end

		@@litters = {}
		@@litter_semaphore = Mutex.new

		# Return a {MU::MommaCat} instance for an existing deploy. Use this instead
		# of using #initialize directly to avoid loading deploys multiple times or
		# stepping on the global context for the deployment you're really working
		# on..
		# @param deploy_id [String]: The deploy ID of the deploy to load.
		# @param set_context_to_me [Boolean]: Whether new MommaCat objects should overwrite any existing per-thread global deploy variables.
		# @return [MU::MommaCat]
		def self.getLitter(deploy_id, set_context_to_me: false)
			if deploy_id.nil? or deploy_id.empty?
				raise MuError, "Cannot fetch a deployment without a deploy_id"
			end
			@@litter_semaphore.synchronize {
				if !@@litters.has_key?(deploy_id)
					@@litters[deploy_id] = MU::MommaCat.new(deploy_id, set_context_to_me: set_context_to_me)
				end
				return @@litters[deploy_id]
			}
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
		attr_accessor :kittens # really want a method only available to :Deploy
		@myhome = Etc.getpwuid(Process.uid).dir
		@nagios_home = "/home/nagios"
		@locks = Hash.new
		@deploy_cache = Hash.new
		@nocleanup = false
		# List the currently held flock() locks.
		def self.locks; @locks end

		# @param deploy_id [String]: The MU identifier of the deployment to load or create.
		# @param create [Boolean]: Create a new deployment instead of searching for an existing one.
		# @param deploy_secret [String]: A secret encrypted by the private key of a deployment we're loading. Used to validate remote requests to bootstrap into this deployment.
		# @param config [Hash]: The full configuration, parsed by {MU::Config}, of this deployment. Required when creating a new deployment.
		# @param environment [String]: The environment of a deployment to create.
		# @param ssh_key_name [String]: Required when creating a new deployment.
		# @param ssh_private_key [String]: Required when creating a new deployment.
		# @param ssh_public_key [String]: SSH public key for authorized_hosts on clients.
		# @param verbose [Boolean]: Enable verbose log output.
		# @param nocleanup [Boolean]: Skip automatic cleanup of failed resources
		# @param deployment_data [Hash]: Known deployment data.
		# @return [void]
		def initialize(deploy_id,
				create: false,
				deploy_secret: deploy_secret,
				config: nil,
				environment: environment = "dev",
				ssh_key_name: ssh_key_name = nil,
				ssh_private_key: ssh_private_key = nil,
				ssh_public_key: ssh_public_key = nil,
				verbose: false,
				nocleanup: false,
				set_context_to_me: true,
				deployment_data: deployment_data = Hash.new,
				mu_user: nil
			)
			verbose = true
			if deploy_id.nil? or deploy_id.empty?
				raise DeployInitializeError, "MommaCat objects must specify a deploy_id"
			end
			set_context_to_me = true if create
			if set_context_to_me
				MU.setVar("chef_user", mu_user) if !mu_user.nil?
				if MU.chef_user != "mu"
					MU.setVar("dataDir", Etc.getpwnam(MU.chef_user).dir+"/.mu/var")
				else
					MU.setVar("dataDir", MU.mainDataDir)
				end
				MU.setVar("mommacat", self)
				MU.setVar("deploy_id", deploy_id)
				MU.setVar("environment", environment)
			end

			@deploy_id = deploy_id
			@kitten_semaphore = Mutex.new
			@kittens = {}
			@original_config = config
			@nocleanup = nocleanup
			@@deploy_struct_semaphore = Mutex.new
			@secret_semaphore = Mutex.new
			@notify_semaphore = Mutex.new
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
			if create 
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
			  @ssh_key_name, @ssh_private_key, @ssh_public_key = self.SSHKey
				if !File.exist?(deploy_dir+"/private_key")
					@private_key, @public_key = createDeployKey
				end
				MU.log "Creating deploy secret for #{MU.deploy_id}"
				@deploy_secret = Password.random(256)
				begin
					MU::Cloud::AWS.s3(MU.myRegion).put_object(
						acl: "private",
						bucket: MU.adminBucketName,
						key: "#{@deploy_id}-secret",
						body: "#{@deploy_secret}"
					)
				rescue Aws::S3::Errors::PermanentRedirect => e
					raise DeployInitializeError, "Got #{e.inspect} trying to write #{@deploy_id}-secret to #{MU.adminBucketName}"
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
			if !create and @deployment and @original_config
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
								MU.log "Failed to locate original config for #{attrs[:cfg_name]} #{res_name} in #{@deploy_id}", MU::WARN if type != "firewall_rules" # XXX shaddap
								next
							end
							begin
								# Load up MU::Cloud objects for all our kittens in this deploy
								if attrs[:has_multiples]
									data.each_pair { |mu_name, actual_data|
										attrs[:interface].new(mommacat: self, kitten_cfg: orig_cfg, mu_name: mu_name)
									}
								else
									attrs[:interface].new(mommacat: self, kitten_cfg: orig_cfg, mu_name: data['mu_name'])
								end
							rescue Exception => e
								MU.log "Failed to load existing resource #{mu_name} in #{@deploy_id}", MU::WARN
							end
						}
					end
				}
			end

# XXX this .owned? method may get changed by the Ruby maintainers
			if !@@litter_semaphore.owned?
				@@litter_semaphore.synchronize {
					@@litters[@deploy_id] = self
				}
			end
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
			has_multiples = false
			MU::Cloud.resource_types.each_pair { |name, cloudclass|
				if name == type.to_sym or
						cloudclass[:cfg_name] == type or
						cloudclass[:cfg_plural] == type
					type = cloudclass[:cfg_plural]
					has_multiples = cloudclass[:has_multiples]
					break
				end
			}
			@kitten_semaphore.synchronize {
				@kittens[type] = {} if @kittens[type].nil?
				if has_multiples
					@kittens[type][name] = {} if @kittens[type][name].nil?
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
				MU.log e.inspect, MU::ERR
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

		# Generate a name string for a resource, incorporate the MU identifier
		# for this deployment. Will dynamically shorten the name to fit for
		# restrictive uses (e.g. Windows local hostnames, Amazon Elastic Load
		# Balancers).
		# @param name [String]: The shorthand name of the resource, usually the value of the "name" field in an Mu resource declaration.
		# @param max_length [Integer]: The maximum length of the resulting resource name.
		# @param need_unique_string [Boolean]: Whether to forcibly append a random three-character string to the name to ensure it's unique. Note that this behavior will be automatically invoked if the name must be truncated.
		# @return [String]: A full name string for this resource
		def self.getResourceName(name, max_length: 255, need_unique_string: false, use_unique_string: nil, reuse_unique_string: false)
			if name.nil?
				raise MuError, "Got no argument to MU::MommaCat.getResourceName"
			end
			if MU.appname.nil? or MU.environment.nil? or  MU.timestamp.nil? or  MU.seed.nil?
				raise MuError, "Missing global variables in thread #{Thread.current.object_id} for #{MU.deploy_id}" if !MU.deploy_id.nil?
			end

			muname = nil
			if need_unique_string
				reserved = 4
			else
				reserved = 0
			end

			# First, pare down the base name string until it will fit
			basename = MU.appname.upcase + "-" + MU.environment.upcase + "-" + MU.timestamp + "-" + MU.seed.upcase + "-" + name.upcase
			begin
				if (basename.length + reserved) > max_length
					MU.log "Stripping name down from #{basename}[#{basename.length.to_s}] (reserved: #{reserved.to_s}, max_length: #{max_length.to_s})", MU::DEBUG
					if basename == MU.appname.upcase + "-" + MU.seed.upcase + "-" + name.upcase
						# If we've run out of stuff to strip, truncate what's left and
						# just leave room for the deploy seed and uniqueness string. This
						# is the bare minimum, and probably what you'll see for most Windows
						# hostnames.
						basename = name.upcase + "-" + MU.appname.upcase
						basename.slice!((max_length-(reserved+3))..basename.length)
						basename.sub!(/-$/, "")
						basename = basename + "-" + MU.seed.upcase
					else
						# If we have to strip anything, assume we've lost uniqueness and
						# will have to compensate with #genUniquenessString.
						need_unique_string = true
						reserved = 4
						basename.sub!(/-[^-]+-#{MU.seed.upcase}-#{Regexp.escape(name.upcase)}$/, "")
						basename = basename + "-" + MU.seed.upcase + "-" + name.upcase
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
						unique_string = genUniquenessString
						muname = basename + "-" + unique_string
					end while !allocateUniqueResourceName(muname)
					@unique_map_semaphore.synchronize {
						@name_unique_str_map[muname] = unique_string
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
		def groomNode(cloud_id, name, type, mu_name: mu_name, reraise_fail: false, sync_wait: true)

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
				puts "------------------------------"
				puts "Open flock() locks:"
				pp MU::MommaCat.locks
				puts "------------------------------"
				return
			end
			loadDeploy

			# XXX this is to stop Net::SSH from killing our entire stack when it 
			# throws an exception. See MU-139 in JIRA. Far as we can tell, it's
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

			if !mu_name.nil? and @kittens["servers"].has_key?(name) and @kittens["servers"][name].has_key?(mu_name)
				kitten = @kittens["servers"][name][mu_name]
				MU.log "Re-grooming #{mu_name}", details: kitten.deploydata
			else
				first_groom = true
				@original_config[type+"s"].each { |svr|
					if svr['name'] == name
						svr["instance_id"] = cloud_id
						kitten = MU::Cloud::Server.new(mommacat: self, kitten_cfg: svr, cloud_id: cloud_id)
						MU.log "Grooming #{kitten.mu_name} for the first time", details: svr
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
					puts "------------------------------"
					puts "Open flock() locks:"
					pp MU::MommaCat.locks
					puts "------------------------------"
					return
				end
				MU::MommaCat.unlock(cloud_id+"-create")

				if !kitten.postBoot(cloud_id)
					MU.log "#{mu_name} is already being groomed, skipping", MU::NOTICE
					MU::MommaCat.unlockAll
					puts "------------------------------"
					puts "Open flock() locks:"
					pp MU::MommaCat.locks
					puts "------------------------------"
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

			MU::MommaCat.unlock(cloud_id+"-mommagroom")
			MU::MommaCat.syncMonitoringConfig(false)
			MU::MommaCat.createStandardTags(cloud_id, region: kitten.config["region"])
			MU.log "Grooming complete for '#{name}' mu_name on \"#{MU.handle}\" (#{MU.deploy_id})"
			MU::MommaCat.unlockAll
			if first_groom
#				sendAdminMail("Grooming complete for '#{name}' mu_name on deploy \"#{MU.handle}\" (#{MU.deploy_id})", data: kitten.deploydata.merge(MU.structToHash(instance)))
# XXX pass the kitten object, actually. can do more interesting things with it once inside
			end
			return
		end

		# Return the parts and pieces of this deploy's node ssh key set. Generate 
		# or load if that hasn't been done already.
		def SSHKey
			return [@ssh_key_name, @ssh_private_key, @ssh_public_key] if !@ssh_key_name.nil?
		  @ssh_key_name="deploy-#{MU.deploy_id}"
		
		  if !File.directory?("#{Dir.home}/.ssh") then
				MU.log "Creating #{Dir.home}/.ssh", MU::DEBUG
		    Dir.mkdir("#{Dir.home}/.ssh", 0700)
		  end
			if !File.exists?("#{Dir.home}/.ssh/#{@ssh_key_name}")
				MU.log "Generating SSH key #{@ssh_key_name}"
				%x{/usr/bin/ssh-keygen -N "" -f #{Dir.home}/.ssh/#{@ssh_key_name}}
			end
			@ssh_public_key = File.read("#{Dir.home}/.ssh/#{@ssh_key_name}.pub")
			@ssh_public_key.chomp!
			@ssh_private_key = File.read("#{Dir.home}/.ssh/#{@ssh_key_name}")
			@ssh_private_key.chomp!

			# XXX only call this if we're creating AWS EC2 resources
			MU::Cloud::AWS.createEc2SSHKey(@ssh_key_name, @ssh_public_key)

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
		def self.unlock(id)
			raise MuError, "Can't pass a nil id to MU::MommaCat.unlock" if id.nil?
			@lock_semaphore.synchronize {
				return if @locks.nil? or @locks[Thread.current.object_id].nil? or @locks[Thread.current.object_id][id].nil?
			}
			MU.log "Releasing lock on #{deploy_dir(MU.deploy_id)}/locks/#{id}.lock (thread #{Thread.current.object_id})", MU::DEBUG
			begin
				@locks[Thread.current.object_id][id].flock(File::LOCK_UN)
				@locks[Thread.current.object_id][id].close
				if !@locks[Thread.current.object_id].nil?
					@locks[Thread.current.object_id].delete(id)
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

		# Iterate over all known deployments and look for instances that have been
		# terminated, but not yet cleaned up, then clean them up.
		def self.cleanTerminatedInstances
			return if @ranalready
			@ranalready = true
			MU.log "Checking for harvested instances in need of cleanup", MU::DEBUG
			parent_thread_id = Thread.current.object_id
			cleanup_threads = []
			purged = 0
			MU::MommaCat.listDeploys.each { |deploy_id|
				cleanup_threads << Thread.new {
					MU.dupGlobals(parent_thread_id)
					deploy = MU::MommaCat.getLitter(deploy_id, set_context_to_me: true)
					if deploy.kittens.has_key?("servers")
MU.log "#{deploy.deploy_id}", MU::NOTICE, details: deploy.kittens["servers"]
						deploy.kittens["servers"].each_pair { |nodeclass, servers|
							servers.each_pair { |mu_name, server|
								if !server.cloud_id
									MU.log "Checking for deletion of #{mu_name}, but unable to fetch its cloud_id", MU::ERR, details: server
								elsif !server.active?
									MU.log "DELETING #{server} (#{nodeclass}), formerly #{server.cloud_id}", MU::ERR
									server.groomer.cleanup
									deploy.notify("servers", nodeclass, mu_name, remove: true)
									deploy.sendAdminMail("Retired terminated node #{mu_name}", data: server)
									purged = purged + 1
								end
							}
						}
					end
				}
			}
			cleanup_threads.each { |t|
				t.join
			}

			MU::MommaCat.syncMonitoringConfig if purged > 0
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
		# @return [Array<MU::Cloud>]
		def self.findStray(cloud,
												type,
												deploy_id: nil,
												name: nil,
												mu_name: nil,
												cloud_id: nil,
												region: nil,
												tag_key: nil,
												tag_value: nil,
												allow_multi: false,
												calling_deploy: MU.mommacat
											)
begin
			resourceclass = MU::Cloud.loadCloudType(cloud, type)
			cloudclass = Object.const_get("MU").const_get("Cloud").const_get(cloud)
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

			if !deploy_id.nil? and !calling_deploy.nil? and
					calling_deploy.deploy_id == deploy_id and (!name.nil? or !mu_name.nil?)
				handle = calling_deploy.findLitterMate(type: type, name: name, mu_name: mu_name)
				return [handle] if !handle.nil?
			end

			kittens = {}
			# Search our deploys for matching resources
			if deploy_id or name or mu_name
				mu_descs = MU::MommaCat.getResourceMetadata(resourceclass.cfg_plural, name: name, deploy_id: deploy_id, mu_name: mu_name)
				mu_descs.each_pair { |found_deploy, matches|
					momma = MU::MommaCat.getLitter(found_deploy)

					# If we found exactly one match in this deploy, use its metadata to
					# guess at resource names we weren't told.
					if matches.size == 1 and name.nil? and mu_name.nil?
						straykitten = momma.findLitterMate(type: type, name: matches.first["name"], cloud_id: matches.first["cloud_id"])
					else
						straykitten = momma.findLitterMate(type: type, name: name, mu_name: mu_name)
					end
					if straykitten.nil?
						MU.log "Failed to locate a kitten from deploy_id: #{deploy_id}, name: #{name}, mu_name: #{mu_name}, despite having found metadata", MU::ERR, details: matches
						raise MuError, "I can't find #{mu_name} anywhere" if !mu_name.nil?
						next
					end
					kittens[straykitten.cloud_id] = straykitten
					# Peace out if we found the exact resource we want
					if cloud_id and straykitten.cloud_id == cloud_id
						return [straykitten]
					elsif !cloud_id and mu_descs.size == 1 and matches.size == 1
						return [straykitten]
					end
				}
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
			if cloud_id or (tag_key and tag_value)
				regions = []
				begin
					if region
						regions << region
					else
						regions = cloudclass.listRegions
					end
				rescue NoMethodError # Not all cloud providers have regions
					regions = [""]
				end

				cloud_descs = {}
				regions.each { |r|
					cloud_descs[r] = resourceclass.find(cloud_id: cloud_id, region: r, tag_key: tag_key, tag_value: tag_value)
				}
				regions.each { |r|
					next if cloud_descs[r].nil?
					cloud_descs[r].each_pair { |kitten_cloud_id, descriptor|
						# We already have a MU::Cloud object for this guy, use it
						if kittens.has_key?(kitten_cloud_id)
							matches << kitten[kitten_cloud_id]
						# If we don't have a MU::Cloud object, manufacture a dummy one
						elsif kittens.size == 0
							if name.nil? or name.empty?
								name = "#dummy"
							end
							cfg = { "name" => name, "cloud" => cloud, "region" => r }
							matches << resourceclass.new(mommacat: calling_deploy, kitten_cfg: cfg, cloud_id: kitten_cloud_id)
						end
					}
				}
			end
rescue Exception => e
MU.log e.inspect, MU::ERR, details: e.backtrace
end
#			pp matches
			matches
		end

		# Return the resource object of another member of this deployment
		# @param type [String,Symbol]: The type of resource
		# @param name [String]: The name of the resource as defined in its 'name' Basket of Kittens field
		# @param mu_name [String]: The fully-resolved and deployed name of the resource
		# @param created_only [Boolean]: Only return the littermate if its cloud_id method returns a value
		# @return [MU::Cloud]
		def findLitterMate(type: nil, name: nil, mu_name: nil, created_only: false)
			has_multiples = false
			MU::Cloud.resource_types.each_pair { |name, cloudclass|
				if name == type.to_sym or
						cloudclass[:cfg_name] == type or
						cloudclass[:cfg_plural] == type
					type = cloudclass[:cfg_plural]
					has_multiples = cloudclass[:has_multiples]
					break
				end
			}

			@kitten_semaphore.synchronize {
				if !@kittens.has_key?(type)
					return nil
				end

				@kittens[type].each { |sib_class, data|
					if has_multiples
						data.each_pair { |sib_mu_name, obj|
							if !mu_name.nil? and mu_name == sib_mu_name
								return obj if !created_only or !obj.cloud_id.nil?
							end
						}
					else
						if !name.nil? and sib_class == name
							return data if !created_only or !data.cloud_id.nil?
						end
					end
				}
			}
			return nil
		end

		# Add or remove a resource's metadata to this deployment's structure and
		# flush it to disk.
		# @param res_type [String]: The type of resource (e.g. *server*, *database*).
		# @param key [String]: The name field of this resource.
		# @param data [Hash]: The resource's metadata.
		# @param remove [Boolean]: Remove this resource from the deploy structure, instead of adding it.
		# @return [void]
		def notify(type, key, data, remove: remove = false, sub_key: nil)
			MU::MommaCat.lock("deployment-notification")
			changed = false
			loadDeploy(true) # make sure we're saving the latest and greatest
			has_multiples = false
			MU::Cloud.resource_types.each_pair { |res_classname, attrs|
				if res_classname == type.to_sym or
						attrs[:cfg_name] == type or
						attrs[:cfg_plural] == type
					type = attrs[:cfg_plural]
					has_multiples = attrs[:has_multiples]
					break
				end
			}
			if !remove
				if data.nil?
					MU.log "MU::MommaCat.notify called to add to deployment struct, but no data provided", MU::WARN
					return
				end
				@deployment[type] = {} if @deployment[type].nil?
				if has_multiples
					@deployment[type][key] = {} if @deployment[type][key].nil?
					if @deployment[type][key].is_a?(Hash) and @deployment[type][key].has_key?("mu_name")
						olddata = @deployment[type][key].dup
						@deployment[type][key][olddata["mu_name"]] = olddata
					end
					changed = true if @deployment[type][key][data["mu_name"]] != data
					@deployment[type][key][data["mu_name"]] = data
					MU.log "Adding to @deployment[#{type}][#{key}][#{data["mu_name"]}]", MU::DEBUG, details: data
				else
					changed = true if @deployment[type][key] != data
					@deployment[type][key] = data
					MU.log "Adding to @deployment[#{type}][#{key}]", MU::DEBUG, details: data
				end
			else
				have_deploy = true
				if @deployment[type].nil? or @deployment[type][key].nil?
					if !sub_key.nil?
						MU.log "MU::MommaCat.notify called to remove #{type} #{key} #{sub_key} deployment struct, but no such data exist", MU::WARN
					else
						MU.log "MU::MommaCat.notify called to remove #{type} #{key} deployment struct, but no such data exist", MU::WARN
					end

					have_deploy = false
				end

				if !sub_key.nil? and have_deploy
					MU.log "Removing @deployment[#{type}][#{key}][#{sub_key}]", MU::DEBUG, details: @deployment[type][key][sub_key]
					changed = true
					@deployment[type][key].delete(sub_key)
				else
					MU.log "Removing @deployment[#{type}][#{key}]", MU::DEBUG, details: @deployment[type][key]
					changed = true
					@deployment[type].delete(key)
				end

				# scrape vault traces out of basket_of_kittens.json too
				if type == "servers" or type == "server_pools" and !sub_key.nil?
					["servers", "server_pools"].each { |svr_class|
						if !@original_config[svr_class].nil?
							@original_config[svr_class].map! { |server|
								if !server['vault_access'].nil? 
									deletia = []
									server['vault_access'].each { |vault|
										if vault["vault"] == sub_key
											deletia << vault
										end
									}
									deletia.each { |drop_vault|
										changed = true
										MU.log "Removing vault references to #{sub_key} from #{svr_class} #{server['name']}"
										server['vault_access'].delete(drop_vault)
									}
								end
								server
							}

						end
					}
				end
			end
			save!(key) if changed
			MU::MommaCat.unlock("deployment-notification")
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
			MU::Cloud.resource_types.each_pair { |res_classname, attrs|
				if res_classname == type.to_sym or
						attrs[:cfg_name] == type or
						attrs[:cfg_plural] == type
					type = attrs[:cfg_plural]
					break
				end
			}

			deploy_root = File.expand_path(MU.dataDir+"/deployments")
			if Dir.exists?(deploy_root)
				Dir.entries(deploy_root).each { |deploy|
					this_deploy_dir = deploy_root+"/"+deploy
					next if deploy == "." or deploy == ".." or !Dir.exists?(this_deploy_dir) 
					if !File.size?(this_deploy_dir+"/deployment.json")
						MU.log "#{this_deploy_dir}/deployment.json doesn't exist, skipping when loading cache", MU::WARN
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
#									if !mu_name.nil? and nodename == mu_name
#										return { deploy => [data] }
#									end
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
											return { deploy => [data] }
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
				matches[deploy_id] = [] if !matches.has_key?(deploy_id)
				if !@deploy_cache[deploy_id]['data'].nil? and
						!@deploy_cache[deploy_id]['data'][type].nil? 
					if !name.nil? 
						if !@deploy_cache[deploy_id]['data'][type][name].nil?
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

		# Tag a resource. Defaults to applying our MU deployment identifier, if no
		# arguments other than the resource identifier are given.
		#
		# @param resource [String]: The cloud provider identifier of the resource to tag
		# @param tag_name [String]: The name of the tag to create
		# @param tag_value [String]: The value of the tag
		# @param region [String]: The cloud provider region
		# @return [void]
		def self.createTag(resource,
									tag_name="MU-ID",
									tag_value=MU.deploy_id,
									region: MU.curRegion)
			attempts = 0 

			begin
			  MU::Cloud::AWS.ec2(region).create_tags(
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
		end

		# Tag a resource with all of our standard identifying tags.
		#
		# @param resource [String]: The cloud provider identifier of the resource to tag
		# @param region [String]: The cloud provider region
		# @return [void]
		def self.createStandardTags(resource, region: MU.curRegion)
			tags = []
			listStandardTags.each_pair { |name, value|
				tags << { key: name, value: value }
			}

			attempts = 0
			begin
			  MU::Cloud::AWS.ec2(region).create_tags(
				  resources: [resource],
				  tags: tags
				)
			rescue Aws::EC2::Errors::ServiceError => e
				MU.log "Got #{e.inspect} tagging #{resource} in #{region}, will retry", MU::WARN, details: caller.concat(tags) if attempts > 1
				if attempts < 5
					attempts = attempts + 1
					sleep 15
					retry
				else
					raise e
				end
			end
			MU.log "Created standard tags for resource #{resource}", MU::DEBUG, details: caller
		end

		# List the name/value pairs for our standard set of resource tags, which
		# should be applied to all taggable cloud provider resources.
		# @return [Hash<String,String>]
		def self.listStandardTags
			return {
				"MU-ID" => MU.deploy_id,
				"MU-HANDLE" => MU.handle,
				"MU-APP" => MU.appname,
				"MU-ENV" => MU.environment,
				"MU-MASTER-NAME" => Socket.gethostname,
				"MU-MASTER-IP" => MU.mu_public_ip,
				"MU-OWNER" => MU.chef_user
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
			node, config, deploydata, instance = server.describe
			nat_ssh_key, nat_ssh_user, nat_ssh_host, canonical_addr, ssh_user, ssh_key_name = server.getSSHConfig

			mu_zone = MU::Cloud::DNSZone.find(cloud_id: "platform-mu").values.first
			if !mu_zone.nil?
				MU::Cloud::DNSZone.genericMuDNSEntry(name: node, target: server.canonicalIP, cloudclass: MU::Cloud::Server, sync_wait: sync_wait)
			else
				MU::MommaCat.addInstanceToEtcHosts(server.canonicalIP, node)
			end

			MU::MommaCat.removeHostFromSSHConfig(node)
# XXX add names paramater with useful stuff
			MU::MommaCat.addHostToSSHConfig(server)
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
			nat_ssh_key, nat_ssh_user, nat_ssh_host, canonical_ip, ssh_user, ssh_key_name = server.getSSHConfig

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

			  File.open(ssh_conf, 'a') { |ssh_config|
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
			return if MU.chef_user != "mu"
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
		# *TODO* this is a placeholder until we get something real, probably
		# involving Route 53.
		# @param public_ip [String]: The node's IP address
		# @param chef_name [String]: The node's Chef node name
		# @param system_name [String]: The node's local system name
		# @return [void]
		def self.addInstanceToEtcHosts(public_ip, chef_name = nil, system_name = nil)
			return if MU.chef_user != "mu"

		  # XXX cover ipv6 case
		  if public_ip.nil? or !public_ip.match(/^\d+\.\d+\.\d+\.\d+$/) or (chef_name.nil? and system_name.nil?)
		    raise MuError, "addInstanceToEtcHosts requires public_ip and one or both of chef_name and system_name!"
		  end
		  if chef_name == "localhost" or system_name == "localhost"
		    raise MuError, "Can't set localhost as a name in addInstanceToEtcHosts"
		  end
		  File.readlines("/etc/hosts").each { |line|
		    if line.match(/^#{public_ip} /) or (chef_name != nil and line.match(/ #{chef_name}(\s|$)/)) or (system_name != nil and line.match(/ #{system_name}(\s|$)/))
					MU.log("Attempt to add duplicate /etc/hosts entry: #{public_ip} #{chef_name} #{system_name}", MU::WARN)
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

		# Send a notification to a deployment's administrators.
		# @param subject [String]: The subject line of the message.
		# @param msg [String]: The message body.
		# @param data [Array]: Supplemental data to add to the message body.
		# @param debug [Boolean]: If set, will include the full deployment structure and original {MU::Config}-parsed configuration.
		# @return [void]
		def sendAdminMail(subject, msg: msg = "", data: data = [], debug: debug = false)
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
			if !data.nil?
				message = message + "\n\n**** Supplemental data:\n" + PP.pp(data, "")
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

			tries = 0
			begin
				first_ltr = @words.select { |word| word.match(/^#{seed[0]}/i) }
				word_one = first_ltr.shuffle.first
				# If we got a paired set that happen to match our letters, go with it
				if !word_one.nil? and word_one.match(/-#{seed[1]}/)
					word_one, word_two = word_one.split(/-/)
				else
					second_ltr = @words.select { |word| word.match(/^#{seed[1]}/i) and !word.match(/-/i) }
					word_two = second_ltr.shuffle.first
				end
				tries = tries + 1
			end while tries < 50 and (word_one.nil? or word_two.nil? or word_one.match(/-/) or (require_cat_words and !@catwords.include?(word_one) and !@catwords.include?(word_two)))

			if tries >= 50 and (word_one.nil? or word_two.nil?)
				MU.log "I failed to generated a valid handle, faking it", MU::ERR
				return "#{seed[0].capitalize} #{seed[1].capitalize}"
			end

			return "#{word_one.capitalize} #{word_two.capitalize}"
		end

		# Punch AWS security group holes for client nodes to talk back to us.
		# @return [void]
		def self.openFirewallForClients
return
# XXX need to move this into AWS-specific module and only call when relevant
			MU::Cloud.loadCloudType("AWS", :FirewallRule)
			if File.exists?(Etc.getpwuid(Process.uid).dir+"/.chef/knife.rb")
				Chef::Config.from_file(Etc.getpwuid(Process.uid).dir+"/.chef/knife.rb")
			end
			Chef::Config[:environment] = MU.environment

			# This is the set of (TCP) ports we're opening to clients. We assume that
			# we can and and remove these without impacting anything a human has
			# created.

			my_ports = [10514]

			my_instance_id = MU.getAWSMetaData("instance-id")
			my_client_sg_name = "Mu Client Rules for #{MU.mu_public_ip}"
			my_sgs = Array.new

			MU.setVar("curRegion", MU.myRegion) if !MU.myRegion.nil?

			resp = MU::Cloud::AWS.ec2.describe_instances(instance_ids: [my_instance_id])
			instance = resp.reservations.first.instances.first

			instance.security_groups.each { |sg|
				my_sgs << sg.group_id
			}
			resp = MU::Cloud::AWS.ec2.describe_security_groups(
				group_ids: my_sgs,
				filters:[
					{ name: "tag:MU-MASTER-IP", values: [MU.mu_public_ip] },
					{ name: "tag:Name", values: [my_client_sg_name] }
				]
			)

			if resp.nil? or resp.security_groups.nil? or resp.security_groups.size == 0
				if instance.vpc_id.nil?
					sg_id = my_sgs.first
					resp = MU::Cloud::AWS.ec2.describe_security_groups(group_ids: [sg_id])
					group = resp.security_groups.first
					MU.log "We don't have a security group named '#{my_client_sg_name}' available, and we are in EC2 Classic and so cannot create a new group. Defaulting to #{group.group_name}.", MU::NOTICE
				else
					group = MU::Cloud::AWS.ec2.create_security_group(
						group_name: my_client_sg_name,
						description: my_client_sg_name,
						vpc_id: instance.vpc_id
					)
					sg_id = group.group_id
					my_sgs << sg_id
					MU::MommaCat.createTag sg_id, "Name", my_client_sg_name
					MU::MommaCat.createTag sg_id, "MU-MASTER-IP", MU.mu_public_ip
					MU::Cloud::AWS.ec2.modify_instance_attribute(
						instance_id: my_instance_id,
						groups: my_sgs
					)
				end
			elsif resp.security_groups.size == 1
				sg_id = resp.security_groups.first.group_id
				resp = MU::Cloud::AWS.ec2.describe_security_groups(group_ids: [sg_id])
				group = resp.security_groups.first
			else
				MU.log "Found more than one security group named #{my_client_sg_name}, aborting", MU::ERR
				exit 1
			end
			
			begin
				MU.log "Using AWS Security Group '#{group.group_name}' (#{sg_id})"
			rescue NoMethodError
				MU.log "Using AWS Security Group #{sg_id}"
			end

			allow_ips = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
			nodelist = `#{MU::Config.knife} node list`.split(/\n/)
			nodelist.each { |node|
				begin
					chef_node = Chef::Node.load(node)
				rescue URI::InvalidURIError => e
					MU.log "Error loading node '#{node}' while opening client firewall holes: #{e.inspect}", MU::WARN
					next
				end
				if !chef_node[:ec2].nil?
					allow_ips << chef_node[:ec2][:public_ip_address] + "/32" if !chef_node[:ec2][:public_ip_address].nil?
				end
			}
			allow_ips.uniq!

			my_ports.each { |port|
				begin
					group.ip_permissions.each { |rule|
						if rule.ip_protocol == "tcp" and
							rule.from_port == port and rule.to_port == port
							MU.log "Revoking old rules for port #{port.to_s} from #{sg_id}", MU::NOTICE
							begin
							MU::Cloud::AWS.ec2.revoke_security_group_ingress(
								group_id: sg_id,
								ip_permissions: [
									{
										ip_protocol: "tcp",
										from_port: port,
										to_port: port,
										ip_ranges: MU.structToHash(rule.ip_ranges)
									}
								]
							)
							rescue Aws::EC2::Errors::InvalidPermissionNotFound => e
								MU.log "Permission disappeared from #{sg_id} (port #{port.to_s}) before I could remove it", MU::WARN, details: MU.structToHash(rule.ip_ranges)
							end
						end
					}
				rescue NoMethodError
# XXX this is ok
				end
				MU.log "Adding current IP list to allow rule for port #{port.to_s} in #{sg_id}", details: allow_ips
				rules = [
					{
						"hosts" => allow_ips,
						"proto" => "tcp",
						"port" => 10514
					}
				]

				ec2_rules = MU::Cloud::AWS::FirewallRule.convertToEc2(rules, region: MU.myRegion)
				MU::Cloud::AWS.ec2(MU.myRegion).authorize_security_group_ingress(
					group_id: sg_id,
					ip_permissions: ec2_rules
				)
			}
		end

		# Ensure that the Nagios configuration local to the MU master has been
		# updated, and make sure Nagios has all of the ssh keys it needs to tunnel
		# to client nodes.
		# @return [void]
		def self.syncMonitoringConfig(blocking = true)
			# XXX
			return
			return if Etc.getpwuid(Process.uid).name != "root" or MU.chef_user != "mu"
			parent_thread_id = Thread.current.object_id
			nagios_threads = []
			nagios_threads << Thread.new {
				MU.dupGlobals(parent_thread_id)
				MU.log "Updating Nagios monitoring config, this may take a while..."
				system("#{MU::Groomer::Chef.chefclient} -o 'recipe[mu-master::update_nagios_only]' 2>&1 > /dev/null")
				if !Dir.exists?("#{@nagios_home}/.ssh")
					Dir.mkdir("#{@nagios_home}/.ssh", 0711)
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
				mu_zone = MU::Cloud::DNSZone.find(cloud_id: "platform-mu").values.first
# XXX need a MU::Cloud::DNSZone.lookup for bulk lookups
# XXX also grab things like mu_windows_name out of deploy data if we can
				parent_thread_id = Thread.current.object_id
				MU::MommaCat.listDeploys.each { |deploy_id|
					begin
						deploy = MU::MommaCat.getLitter(deploy_id)
						if deploy.kittens.has_key?("servers")
							deploy.kittens["servers"].each_pair { |nodeclass, nodes|
								nodes.each_pair { |mu_name, server|
									MU.dupGlobals(parent_thread_id)
									threads << Thread.new {
										MU.log "Adding #{server.mu_name} to #{@nagios_home}/.ssh/config", MU::DEBUG
										MU::MommaCat.addHostToSSHConfig(
											server,
											ssh_dir: "#{@nagios_home}/.ssh",
											ssh_conf: "#{@nagios_home}/.ssh/config.tmp",
											ssh_owner: "nagios"
										)
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
				File.chown(Etc.getpwnam("nagios").uid, Etc.getpwnam("nagios").gid, "#{@nagios_home}/.ssh/config")
				File.rename("#{@nagios_home}/.ssh/config.tmp", "#{@nagios_home}/.ssh/config")
				puts ""
				MU.log "Nagios monitoring config update complete."
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
			deploys = []
			Dir.entries("#{MU.dataDir}/deployments").reverse_each { |muid|
				next if !Dir.exists?("#{MU.dataDir}/deployments/#{muid}") or muid == "." or muid == ".."
				deploys << muid
			}
			return deploys
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


		# Given a Certificate Signing Request, sign it with our internal CA and
		# writers the resulting signed certificate. Only works on local files.
		# @param csr_path [String]: The CSR to sign, as a file.
		def signSSLCert(csr_path)
			# XXX more sanity here, this feels unsafe
			certdir = File.dirname(csr_path)
			certname = File.basename(csr_path, ".csr")
			if File.exists?("#{certdir}/#{certname}.crt")
				MU.log "Not re-signing SSL certificate request #{csr_path}, #{certdir}/#{certname}.crt already exists", MU::WARN
				return
			end
			MU.log "Signing SSL certificate request #{csr_path} with #{MU.mySSLDir}/Mu_CA.pem"

			csr = OpenSSL::X509::Request.new File.read csr_path

			# Load up the Mu Certificate Authority
			cakey = OpenSSL::PKey::RSA.new File.read "#{MU.mySSLDir}/Mu_CA.key"
			cacert = OpenSSL::X509::Certificate.new File.read "#{MU.mySSLDir}/Mu_CA.pem"

			cur_serial = 0
			File.open("#{MU.mySSLDir}/serial", File::CREAT|File::RDWR, 0600) { |f|
				f.flock(File::LOCK_EX)
				cur_serial = f.read.chomp!.to_i
				cur_serial = cur_serial + 1
				f.rewind
				f.truncate(0)
				f.puts cur_serial
				f.flush
				f.flock(File::LOCK_UN)
			}

			# Create a certificate from our CSR, signed by the Mu CA
			cert = OpenSSL::X509::Certificate.new
			cert.serial = cur_serial
			cert.version = 2
			cert.not_before = Time.now
			cert.not_after = Time.now + 1800000 # 500 days
			cert.subject = csr.subject
			cert.public_key = csr.public_key
			cert.issuer = cacert.subject
			cert.sign cakey, OpenSSL::Digest::SHA1.new

			open("#{certdir}/#{certname}.crt", 'w', 0644) { |io|
				io.write cert.to_pem
			}
			if MU.chef_user != "mu"
				owner_uid = Etc.getpwnam(MU.chef_user).uid
				File.chown(owner_uid, nil, "#{certdir}/#{certname}.crt")
			end
		end

		private

		# Make sure deployment data is synchronized to/from each Chef node in the
		# currently-loaded deployment.
		def syncLitter(nodeclasses = [], triggering_node: nil)
			return if MU.syncLitterThread
			svrs = MU::Cloud.resource_types[:Server][:cfg_plural] # legibility shorthand
			if @kittens.nil? or
					@kittens[svrs].nil?
				MU.log "No #{svrs} as yet available in #{@deploy_id}", MU::WARN, details: @kittens
				return
			end
			MU.log "Updating these siblings in #{@deploy_id}: #{nodeclasses.join(', ')}", MU::DEBUG, details: @kittens[svrs]
# XXX add mu_name indirection
			update_servers = []
			if nodeclasses.nil? or nodeclasses.size == 0
				update_servers = @kittens[svrs].values
			else
				@kittens[svrs].each_pair { |mu_name, node|
					if nodeclasses.include?(node.config['name']) and !node.groomer.nil?
						update_servers << node
					end
				}
			end
			return if update_servers.size == 0

			# Merge everyone's deploydata together
			update_servers.each { |sibling|
				mu_name, config, deploydata, cloud_descriptor = sibling.describe
				@deployment[svrs][config['name']][mu_name] = deploydata if !deploydata.nil?
			}
			threads = []
			parent_thread_id = Thread.current.object_id
# XXX apparently we teeter dangerously close to outrunning the system call stack
# here, even though we're not doing anything recursive or even that deep.
# Beware future surprises.
			update_servers.each { |sibling|
				threads << Thread.new {
					MU.dupGlobals(parent_thread_id)
					Thread.current.thread_variable_set("name", "sync-"+sibling.mu_name.downcase)
					MU.setVar("syncLitterThread", true)
					sibling.groomer.run
				}
			}

			threads.each { |t|
				t.join
			}

			MU.log "Synchronization of #{@deploy_id} complete", MU::NOTICE, details: update_servers
		end

		# Check to see whether a given resource name is unique across all
		# deployments on this Mu server. We only enforce this for certain classes
		# of names. If the name in question is available, add it to our cache of
		# said names.  See #{MU::MommaCat.getResourceName}
		# @param name [String]: The name to attempt to allocate.
		# @return [Boolean]: True if allocation was successful.
		def self.allocateUniqueResourceName(name)
			raise MuError, "Cannot call allocateUniqueResourceName without an active deployment" if MU.deploy_id.nil?
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
							MU.log "#{name} is already reserved by another resource on this Mu server.", MU::WARN
							return false
						end
					}
					f.puts name+":"+MU.deploy_id
					return true
				ensure
					f.flock(File::LOCK_UN)
				end
			}
		end

		###########################################################################
		###########################################################################
		def self.deploy_dir(deploy_id)
			raise MuError, "deploy_dir must get a deploy_id if called as class method" if deploy_id.nil?
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
		def deploy_dir
			MU::MommaCat.deploy_dir(@deploy_id)
		end


		def createDeployKey
			key = OpenSSL::PKey::RSA.generate(4096)
			MU.log "Generated deploy key for #{MU.deploy_id}", MU::DEBUG, details: key.public_key.export
			return [key.export, key.public_key.export]
		end

		# Synchronize all in-memory information related to this to deployment to
		# disk.
		def save!(updating_node_type = nil)
			@@deploy_struct_semaphore.synchronize {
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
					if !@deployment['servers'].nil? and @deployment['servers'].keys.size > 0
						# XXX some kind of filter (obey sync_siblings on nodes' configs)
						syncLitter(@deployment['servers'].keys)
					end
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

		end

		###########################################################################
		###########################################################################
		def loadDeploy(deployment_json_only = false, set_context_to_me: true)
			@@deploy_struct_semaphore.synchronize {
				if File.size?(deploy_dir+"/deployment.json")
					deploy = File.open("#{deploy_dir}/deployment.json", File::RDONLY)
					MU.log "Getting lock to read #{deploy_dir}/deployment.json", MU::DEBUG
					deploy.flock(File::LOCK_EX)
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
						Dir.glob("#{deploy_dir}/secrets/#{type}.*"){ |filename|
							base, server = File.basename(filename).split(/\./)
			
							@secrets[type][server] = File.read(filename).chomp!
						}
					}
				end
			}

		end


		@catwords = %w{abyssian acinonyx alley angora bastet bengal birman bobcat bobtail bombay burmese calico chartreux cheetah cheshire cornish-rex curl devon devon-rex dot egyptian-mau feline felix feral fuzzy ginger havana himilayan jaguar japanese-bobtail javanese kitty khao-manee leopard lion lynx maine-coon manx marmalade maru mau mittens moggy munchkin neko norwegian ocelot pallas panther patches paws persian peterbald phoebe polydactyl purr queen quick ragdoll roar russian-blue saber savannah scottish-fold sekhmet serengeti shorthair siamese siberian singapura snowshoe socks sphinx spot stray tabby tail tiger tom tonkinese tortoiseshell turkish-van tuxedo uncia whiskers wildcat yowl}
		@noncatwords = %w{alpha amber auburn azure beta brave bravo brawler charlie chocolate chrome cinnamon corinthian coyote crimson dancer danger dash delta don duet echo edge electric elite enigma eruption eureka fearless foxtrot galvanic gold grace grey horizon hulk hyperion illusion imperative india intercept ivory jade jaeger juliet kaleidoscope kilo lucky mammoth night nova november ocean olive oscar quiescent rhythm rogue romeo ronin royal tacit tango typhoon ultimatum ultra umber upward victor violet vivid vulcan watchman whirlwind wright xenon xray xylem yankee yearling yell yukon zeal zero zippy zodiac}
		@words = @catwords + @noncatwords

	end #class
end #module

