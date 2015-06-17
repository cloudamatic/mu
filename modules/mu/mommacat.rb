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
		class SecretError < MuError
		end

		# Failure to load or create a deploy
		class DeployInitializeError < MuError
		end

		# Failure to groom a node
		class GroomError < MuError
		end

		attr_reader :public_key
		attr_reader :deploy_secret
		attr_reader :deployment
		attr_reader :original_config
		attr_reader :environment
		attr_reader :ssh_key_name
		attr_reader :ssh_public_key
		attr_reader :nocleanup
		attr_reader :mu_id
		@myhome = Etc.getpwuid(Process.uid).dir
		@nagios_home = "/home/nagios"
		@locks = Hash.new
		@deploy_cache = Hash.new
		@nocleanup = false
		# List the currently held flock() locks.
		def self.locks; @locks end

		# @param mu_id [String]: The MU identifier of the deployment to load or create.
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
		def initialize(mu_id,
				create: create = false,
				deploy_secret: deploy_secret,
				config: config = nil,
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
			if mu_id.nil? or mu_id.empty?
				raise DeployInitializeError, "MommaCat objects must specify a mu_id"
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
				MU.setVar("mu_id", mu_id)
				MU.setVar("environment", environment)
			end

			@mu_id = mu_id
			@original_config = config
			@nocleanup = nocleanup
			@deploy_struct_semaphore = Mutex.new
			@secret_semaphore = Mutex.new
			@notify_semaphore = Mutex.new
			@deployment = deployment_data
			@deployment['mu_public_ip'] = MU.mu_public_ip
			@private_key = nil
			@public_key = nil
			@secrets = Hash.new
			@secrets['windows_password'] = Hash.new
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
				path = File.expand_path(MU.dataDir+"/deployments")+"/"+@mu_id
				if !Dir.exist?(path)
					MU.log "Creating #{path}", MU::DEBUG
					Dir.mkdir(path, 0700)
				end
				if @original_config.nil? or !@original_config.is_a?(Hash)
					raise DeployInitializeError, "New MommaCat repository requires config hash"
				end
				if @ssh_key_name.nil? or @ssh_private_key.nil?
					puts @ssh_key_name
					puts @ssh_private_key
					raise DeployInitializeError, "New MommaCat repository requires SSH keys"
				end
				if !File.exist?(deploy_dir+"/private_key")
					@private_key, @public_key = createDeployKey
				end
				MU.log "Creating deploy secret for #{MU.mu_id}"
				@deploy_secret = Password.random(256)
				begin
					MU::Cloud::AWS.s3(MU.myRegion).put_object(
						acl: "private",
						bucket: MU.adminBucketName,
						key: "#{@mu_id}-secret",
						body: "#{@deploy_secret}"
					)
				rescue Aws::S3::Errors::PermanentRedirect => e
					raise DeployInitializeError, "Got #{e.inspect} trying to write #{@mu_id}-secret to #{MU.adminBucketName}"
				end
				save!
			end


			loadDeploy
			if !deploy_secret.nil?
				if !authKey(deploy_secret)
					raise DeployInitializeError, "Invalid or incorrect deploy key."
				end
			end
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
					MU.log "Matched ciphertext for #{MU.mu_id}", MU::INFO
					return true
				else
					MU.log "Mis-matched ciphertext for #{MU.mu_id}", MU::ERR
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
				raise MuError, "Missing global variables in thread #{Thread.current.object_id} for #{MU.mu_id}" if !MU.mu_id.nil?
				raise MuError, "Missing global variables in call to getResourceName"
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
		def saveSecret(instance_id, raw_secret, type)
			if instance_id.nil? or instance_id.empty? or raw_secret.nil? or raw_secret.empty? or type.nil? or type.empty?
				raise SecretError, "saveSecret requires instance_id, raw_secret, and type args"
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


		# Run {MU::Cloud::AWS::Server#postBoot} and {MU::Cloud::AWS::Server#deploy} on a node.
		# @param instance [OpenStruct]: The cloud providor's full descriptor for this node.
		# @param name [String]: The MU resource name of the node being created.
		# @param type [String]: The type of resource that created this node (either *server* or *serverpool*).
		def groomNode(instance, name, type, reraise_fail: false, sync_wait: true)

			if instance.nil?
				raise GroomError, "MU::MommaCat.groomNode requires an AWS instance object"
			end
			if name.nil? or name.empty?
				raise GroomError, "MU::MommaCat.groomNode requires a resource name"
			end
			if type.nil? or type.empty?
				raise GroomError, "MU::MommaCat.groomNode requires a resource type"
			end

			if !MU::MommaCat.lock(instance.instance_id+"-mommagroom", true)
				MU.log "Instance #{instance.instance_id} on #{MU.mu_id} (#{type}: #{name}) is already being groomed, ignoring this extra request.", MU::NOTICE
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
				raise GroomError, "I see no configured resources of type #{type} (bootstrapping #{name})"
			end
			@original_config[type+"s"].each { |svr|
				mylocks = Array.new
				if svr["name"] == name
					cloudclass = MU::Cloud.artifact(svr["cloud"], type)
					serverclass = MU::Cloud.artifact(svr["cloud"], "Server")
					server = svr.dup
					node = nil
					first_groom = true

					# See if this particular instance has been groomed before.
					if !@deployment['servers'].nil? and !@deployment['servers'][name].nil?
						@deployment['servers'][name].each_pair { |nodename, data|
							if data['instance_id'] == instance.instance_id
								node = nodename
								first_groom = false
								MU.log "Re-grooming #{node}", details: data
								if !data['mu_windows_name'].nil? and server['mu_windows_name'].nil?
									server['mu_windows_name'] = data['mu_windows_name']
								end
								break
							end
						}
					end


					if node.nil? or node.empty?
						if type == "server_pool"
							node = MU::MommaCat.getResourceName(name, need_unique_string: true)
						else
							node = MU::MommaCat.getResourceName(name)
						end
						MU.log "Grooming #{node} for the first time", details: server
					end

					server['mu_name'] = node
					server["instance_id"] = instance.instance_id
					begin
						# This is a shared lock with MU::Cloud::AWS::Server.create, to keep from
						# stomping on synchronous deploys that are still running. This
						# means we're going to wait here if this instance is still being
						# bootstrapped by "regular" means.
						if !MU::MommaCat.lock(instance.instance_id+"-create", true)
							MU.log "#{node} is still in mid-creation, skipping", MU::NOTICE
							MU::MommaCat.unlockAll
							puts "------------------------------"
							puts "Open flock() locks:"
							pp MU::MommaCat.locks
							puts "------------------------------"
							return
						end
						MU::MommaCat.unlock(instance.instance_id+"-create")

						if %w{win2k12r2 win2k12 windows}.include? server['platform']
							if (server['mu_windows_name'].nil? or server['mu_windows_name'].empty?) 
								if first_groom
									server['mu_windows_name'] = MU::MommaCat.getResourceName(name, max_length: 15, use_unique_string: MU::MommaCat.name_unique_str_map[node])
								elsif !@deployment.nil? and @deployment.has_key?('servers') and
										@deployment['servers'].has_key?(server['name']) and
										@deployment['servers'][server['name']].has_key?(node)
									server['mu_windows_name'] = @deployment['servers'][server['name']][node]['mu_windows_name']
								end
							end
							if @secrets['windows_password'].has_key?(server["instance_id"])
								server['winpass'] = fetchSecret(server["instance_id"], "windows_password")
							elsif @secrets['windows_password'].has_key?("default")
								server['winpass'] = fetchSecret("default", "windows_password")
							end

						end

						if !serverclass.postBoot(server, instance, @ssh_key_name, sync_wait: sync_wait)
							MU.log "#{node} is already being groomed, skipping", MU::NOTICE
							MU::MommaCat.unlockAll
							puts "------------------------------"
							puts "Open flock() locks:"
							pp MU::MommaCat.locks
							puts "------------------------------"
							return
						end

						# This is a shared lock with MU::Deploy.createResources, simulating
						# the thread logic that tells MU::Cloud::AWS::Server.deploy to wait until its
						# dependencies are ready. We don't, for example, want to start
						# deploying if we rely on an RDS instance that isn't ready yet. We
						# can release this immediately, once we successfully grab it.
						MU::MommaCat.lock("#{cloudclass.name}_#{server["name"]}-dependencies")
						MU::MommaCat.unlock("#{cloudclass.name}_#{server["name"]}-dependencies")

						serverclass.deploy(server, @deployment, keypairname: @ssh_key_name)
					rescue Exception => e
						MU::MommaCat.unlockAll
						if e.class.name != "MU::Cloud::AWS::Server::BootstrapTempFail" and !File.exists?(deploy_dir+"/.cleanup."+instance.instance_id) and !File.exists?(deploy_dir+"/.cleanup")
							MU.log "Grooming FAILED for #{node} (#{e.inspect})", MU::ERR, details: e.backtrace
							sendAdminMail("Grooming FAILED for #{node} on #{MU.appname} \"#{MU.handle}\" (#{MU.mu_id})",
								msg: e.inspect,
								data: e.backtrace,
								debug: true
							)
							raise e if reraise_fail
						else
							MU.log "Grooming of #{node} interrupted by cleanup or planned reboot"
						end
						return
					end

					MU::MommaCat.unlock(instance.instance_id+"-mommagroom")
					MU::MommaCat.syncMonitoringConfig(false)
					MU::MommaCat.createStandardTags(instance.instance_id, region: server["region"])
					MU.log "Grooming complete for '#{name}' node on \"#{MU.handle}\" (#{MU.mu_id})"
					MU::MommaCat.unlockAll
					if first_groom
						sendAdminMail("Grooming complete for '#{name}' node on deploy \"#{MU.handle}\" (#{MU.mu_id})", data: server.merge(MU.structToHash(instance)))
					end
					return
				end
			}
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
						MU.log "Releasing lock on #{deploy_dir(MU.mu_id)}/locks/#{id}.lock (thread #{Thread.current.object_id})", MU::DEBUG
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
				lockdir = "#{deploy_dir(MU.mu_id)}/locks"
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
			MU.log "Releasing lock on #{deploy_dir(MU.mu_id)}/locks/#{id}.lock (thread #{Thread.current.object_id})", MU::DEBUG
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
		# @param mu_id [String]: The deployment identifier to remove.
		def self.purge(mu_id)
			if mu_id.nil? or mu_id.empty?
				raise MuError, "Got nil mu_id in MU::MommaCat.purge"
			end
			# XXX archiving is better than annihilating
			path = File.expand_path(MU.dataDir+"/deployments")
			if Dir.exist?(path+"/"+mu_id)
				unlockAll
				MU.log "Purging #{path}/#{mu_id}" if File.exists?(path+"/"+mu_id+"/deployment.json")

				FileUtils.rm_rf(path+"/"+mu_id, :secure => true)
			end
			if File.exists?(path+"/unique_ids")
				File.open(path+"/unique_ids", File::CREAT|File::RDWR, 0600) { |f|
					newlines = []
					f.flock(File::LOCK_EX)
					f.readlines.each { |line|
						newlines << line if !line.match(/:#{mu_id}$/)
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
			MU::MommaCat.purge(MU.mu_id)
		end

		# Iterate over all known deployments and look for instances that have been
		# terminated, but not yet cleaned up, then clean them up.
		def self.cleanTerminatedInstances
			MU.log "Checking for harvested instances in need of cleanup", MU::DEBUG
			deploys = []
			deploy_root = File.expand_path(MU.dataDir+"/deployments")
			if Dir.exists?(deploy_root)
				Dir.entries(deploy_root).each { |deploy|
					this_deploy_dir = deploy_dir(deploy)
					next if deploy == "." or deploy == ".." or !Dir.exists?(this_deploy_dir) or File.exists?(this_deploy_dir+"/.cleanup")
					deploys << deploy
				}
			end
			cleanup_threads = []
			regions = MU::Cloud::AWS.listRegions
			deploys.each { |deploy|
				known_servers = MU::MommaCat.getResourceDeployStruct("servers", deploy_id: deploy)

				next if known_servers.nil?
				parent_thread_id = Thread.current.object_id
				cleanup_threads << Thread.new {
					MU.dupGlobals(parent_thread_id)
					MU.setVar("mu_id", deploy)
					purged = 0
					known_servers.each { |server_container|
						server_container.each_pair { |nodename, data|
							MU.setVar("curRegion", data['region']) if !data['region'].nil?
							begin
								resp = MU::Cloud::AWS.ec2(MU.curRegion).describe_instances(instance_ids: [data['instance_id']])
								if !resp.nil? and !resp.reservations.nil? and !resp.reservations.first.nil?
									instance = resp.reservations.first.instances.first
								end
							rescue Aws::EC2::Errors::InvalidInstanceIDNotFound => e
								MU.log "Instance #{data['instance_id']} is completely gone already (#{e.inspect})", MU::DEBUG
              rescue Aws::EC2::Errors::InternalError => e
								MU.log "Attempt to describe #{data['instance_id']} generated #{e.inspect}", MU::WARN
								next
							end
							if instance.nil? or instance.state.name == "terminated" or instance.state.name == "terminating"
								MU.log "Retiring #{nodename} (#{data['instance_id']})", MU::NOTICE, details: data
								purged = purged + 1
								kitten_pile = MU::MommaCat.new(deploy)
								conf = Hash.new
								if !kitten_pile.nil? and !kitten_pile.original_config.nil?
									["servers", "server_pools"].each { |res_type|
										if !kitten_pile.original_config[res_type].nil?
											kitten_pile.original_config[res_type].each { |svr|
												if svr['name'] == data['#MU_NODE_CLASS']
													MU::Cloud::AWS::Server.purgeChefResources(nodename, svr['vault_access'])
												end
											}
										end
									}
								end
								MU::Cloud::AWS::Server.terminateInstance(id: data['instance_id'], region: MU.curRegion)
								begin
									kitten_pile.notify("servers", data['#MU_NODE_CLASS'], nodename, remove: true, sub_key: nodename)
									kitten_pile.sendAdminMail("Retired terminated node #{nodename}", data: data)
								rescue Errno::ENOENT => e
									MU.log "Looks like #{nodename} was cleaned up by something else", MU::WARN, details: e.inspect
								end
							end
						}
					}
					MU::MommaCat.syncMonitoringConfig if purged > 0
				}
			}

			cleanup_threads.each { |t|
				t.join
			}

		end

		# Add or remove a resource's metadata to this deployment's structure and
		# flush it to disk.
		# @param res_type [String]: The type of resource (e.g. *server*, *database*).
		# @param key [String]: The MU resource name.
		# @param data [Hash]: The resource's metadata.
		# @param remove [Boolean]: Remove this resource from the deploy structure, instead of adding it.
		# @return [void]
		def notify(res_type, key, data, remove: remove = false, sub_key: nil)
			MU::MommaCat.lock("deployment-notification")
			loadDeploy(true) # make sure we're saving the latest and greatest
			if !remove
				if data.nil?
					MU.log "MU::MommaCat.notify called to add to deployment struct, but no data provided", MU::WARN
					return
				end
				if @deployment[res_type].nil?
					@deployment[res_type] = Hash.new
				end
				@deployment[res_type][key] = data
				MU.log "Adding to @deployment[#{res_type}][#{key}]", MU::DEBUG, details: data
			else
				have_deploy = true
				if @deployment[res_type].nil? or @deployment[res_type][key].nil?
					if !sub_key.nil?
						MU.log "MU::MommaCat.notify called to remove #{res_type} #{key} #{sub_key} deployment struct, but no such data exist", MU::WARN
					else
						MU.log "MU::MommaCat.notify called to remove #{res_type} #{key} deployment struct, but no such data exist", MU::WARN
					end

					have_deploy = false
				end

				if !sub_key.nil? and have_deploy
					MU.log "Removing @deployment[#{res_type}][#{key}][#{sub_key}]", MU::DEBUG, details: @deployment[res_type][key][sub_key]
					@deployment[res_type][key].delete(sub_key)
				else
					MU.log "Removing @deployment[#{res_type}][#{key}]", MU::DEBUG, details: @deployment[res_type][key]
					@deployment[res_type].delete(key)
				end

				# scrape vault traces out of basket_of_kittens.json too
				if res_type == "servers" or res_type == "server_pools" and !sub_key.nil?
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
			save!(key)
			MU::MommaCat.unlock("deployment-notification")
		end

		# Find a resource by its Mu resource name, and return its full
		# deployment structure. If no name is specified, will return all resources
		# of that type in an array. If mu_id is set to nil, will return all
		# matching resources across all deployments in an array.
		# 
		# @param type [String]: The type of resource, e.g. "vpc" or "server."
		# @param name [String]: The Mu resource name, typically the name field of a Basket of Kittens resource declaration.
		# @param deploy_id [String]: The deployment to search. Defaults to the currently loaded deployment.
		# @return [Hash,Array<Hash>]
		def self.getResourceDeployStruct(type, name: nil, deploy_id: MU.mu_id, use_cache: true)
			if type.nil?
				raise MuError, "Can't call getResourceDeployStruct without a type argument"
			end

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
						# Servers have an annoying layer of indirection, because you can
						# have multiple things of the same name (aka node_class). Preserve
						# that when we return these guys as a flat array by sticking it in
						# a special field.
						if !@deploy_cache[deploy].nil? and !@deploy_cache[deploy]['data'].nil? and !@deploy_cache[deploy]['data']['servers'].nil?
							@deploy_cache[deploy]['data']['servers'].each_pair { |node_class, nodes|
								next if nodes.nil? or !nodes.is_a?(Hash)
								nodes.each_pair { |nodename, data|
									next if !data.is_a?(Hash)
									data['#MU_NODE_CLASS'] = node_class
									if !data.has_key?("cloud")
										data["cloud"] = MU::Config.defaultCloud
									end
									data['#MU_CLOUDCLASS'] = MU::Cloud.artifact("AWS", :Server)
								}
							}
						end
					rescue JSON::ParserError => e
						raise MuError, "JSON parse failed on #{this_deploy_dir}/deployment.json\n\n"+File.read("#{this_deploy_dir}/deployment.json")
					end
					lock.flock(File::LOCK_UN)
					lock.close
				}
			end

			if deploy_id.nil?
				matches = []
				@deploy_cache.each_key { |deploy|
					next if !@deploy_cache[deploy].has_key?('data')
					next if !@deploy_cache[deploy]['data'].has_key?(type)
					if !name.nil?
						next if @deploy_cache[deploy]['data'][type][name].nil?
						matches << @deploy_cache[deploy]['data'][type][name].dup
					else
						matches.concat(@deploy_cache[deploy]['data'][type].values)
					end
				}
				return matches
			elsif !@deploy_cache[deploy_id].nil? and
					!@deploy_cache[deploy_id]['data'].nil? and
					!@deploy_cache[deploy_id]['data'][type].nil? 
				if !name.nil? 
					if !@deploy_cache[deploy_id]['data'][type][name].nil?
						return @deploy_cache[deploy_id]['data'][type][name].dup
					else
						return nil
					end
				else
					return @deploy_cache[deploy_id]['data'][type].values
				end
			end
			return nil
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
									tag_value=MU.mu_id,
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
				"MU-ID" => MU.mu_id,
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

		@ssh_semaphore = Mutex.new
		# Insert a definition for a node into our SSH config.
		# @param node [String]: The name of the node.
		# @param private_ip [String]: The node's private IP address.
		# @param private_dns [String]: The node's private DNS name.
		# @param public_ip [String]: The node's public IP address.
		# @param public_dns [String]: The node's public DNS name.
		# @param user [String]: The user on the node which will accept remote logins.
		# @param gateway_ip [String]: The IP address of the bastion/gateway host, if any.
		# @param gateway_user [String]: The user on the bastion/gateway host which will accept proxy requests.
		# @param key_name [String]: The name of the SSH key which will allow us access.
		# @param ssh_dir [String]: The configuration directory of the SSH config to emit.
		# @param ssh_owner [String]: The preferred owner of the SSH configuration files.
		# @return [void]
		def self.addHostToSSHConfig(node, private_ip, private_dns,
				public_ip: "",
				public_dns: "",
				user: "root",
				gateway_ip: nil,
				gateway_user: "ec2-user",
				key_name: "deploy-#{MU.mu_id}",
				ssh_dir: "#{@myhome}/.ssh",
				ssh_conf: "#{@myhome}/.ssh/config",
				ssh_owner: Etc.getpwuid(Process.uid).name,
				timeout: 0
			)
			mu_dns = nil
			if !public_dns.nil?
				mu_dns = MU::Cloud::AWS::DNSZone.genericDNSEntry(node, public_dns, MU::Cloud::Server, noop: true)
			else
				mu_dns = MU::Cloud::AWS::DNSZone.genericDNSEntry(node, private_ip, MU::Cloud::Server, noop: true)
			end
			mu_dns = nil # XXX HD account hack
			if user.nil? or (gateway_user.nil? and !gateway_ip.nil? and (public_ip.nil? or public_ip.empty? and (private_ip != gateway_ip)))
				MU.log "Called addHostToSSHConfig with a missing SSH user argument. addHostToSSHConfig(node: #{node}, private_ip: #{private_ip}, private_dns: #{private_dns}, public_ip: #{public_ip}, public_dns: #{public_dns}, user: #{user}, gateway_ip: #{gateway_ip}, gateway_user: #{gateway_user}, key_name: #{key_name}, ssh_dir: #{ssh_dir}, ssh_conf: #{ssh_conf}, ssh_owner: #{ssh_owner}", MU::ERR, details: caller
				return
			end

			@ssh_semaphore.synchronize {

				if File.exists?(ssh_conf)
				  File.readlines(ssh_conf).each { |line|
				    if line.match(/^Host #{node} /)
							MU.log("Attempt to add duplicate #{ssh_conf} entry for #{node}", MU::WARN)
							return
				    end
				  }
				end

			  File.open(ssh_conf, 'a') { |ssh_config|
				  ssh_config.flock(File::LOCK_EX)
					if !mu_dns.nil? and !mu_dns.empty?
				    ssh_config.puts "Host #{node} #{mu_dns} #{public_ip} #{public_dns}"
					else
				    ssh_config.puts "Host #{node} #{private_ip} #{public_ip} #{private_dns} #{public_dns}"
					end
					if !gateway_ip.nil? and (public_ip.nil? or public_ip.empty? and (private_ip != gateway_ip))
						if !mu_dns.nil? and !mu_dns.empty?
					    ssh_config.puts "  Hostname #{mu_dns}"
						else
					    ssh_config.puts "  Hostname #{private_ip}"
						end
						ssh_config.puts "  ProxyCommand ssh -W %h:%p #{gateway_user}@#{gateway_ip}"
					else
						if !mu_dns.nil? and !mu_dns.empty?
					    ssh_config.puts "  Hostname #{mu_dns}"
						elsif !public_ip.nil? and !public_ip.empty?
					    ssh_config.puts "  Hostname #{public_ip}"
						else
					    ssh_config.puts "  Hostname #{private_ip}"
						end
						if timeout > 0
							ssh_config.puts "  ConnectTimeout #{timeout}"
						end
					end

			    ssh_config.puts "  User #{user}"
# XXX I'd rather add the host key to known_hosts, but Net::SSH is a little dumb
			    ssh_config.puts "  StrictHostKeyChecking no"

				  ssh_config.puts "  IdentityFile #{ssh_dir}/#{key_name}"
					if !File.exist?("#{ssh_dir}/#{key_name}")
						MU.log "SSH private key #{ssh_dir}/#{key_name} does not exist", MU::WARN
					end

			    ssh_config.flock(File::LOCK_UN)
					ssh_config.chown(Etc.getpwnam(ssh_owner).uid, Etc.getpwnam(ssh_owner).gid)
			  }
				MU.log "Wrote #{MU.mu_id} ssh key to #{ssh_dir}/config", MU::DEBUG
				return "#{ssh_dir}/#{key_name}"
			}
		end

		# Clean a node's entries out of /etc/hosts
		# @param node [String]: The node's name
		# @return [void]
		def self.removeInstanceFromEtcHosts(node)
			return if MU.chef_user != "mu"
			hostsfile = "/etc/hosts"
			FileUtils.copy(hostsfile, "#{hostsfile}.bak-#{MU.mu_id}")
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
			rescue Net::SMTPFatalError => e
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

				MU::Cloud::AWS::FirewallRule.addRule(sg_id, allow_ips, port: port)
			}
		end

		# Ensure that the Nagios configuration local to the MU master has been
		# updated, and make sure Nagios has all of the ssh keys it needs to tunnel
		# to client nodes.
		# @return [void]
		def self.syncMonitoringConfig(blocking = true)
			return if Etc.getpwuid(Process.uid).name != "root" or MU.chef_user != "mu"
			parent_thread_id = Thread.current.object_id
			nagios_threads = []
			nagios_threads << Thread.new {
				MU.dupGlobals(parent_thread_id)
				MU.log "Updating Nagios monitoring config, this may take a while..."
				system("#{MU::Config.chefclient} -o 'recipe[mu-master::update_nagios_only]' 2>&1 > /dev/null")
				allnodes = Hash.new
				if Dir.exists?(MU.dataDir+"/deployments")
					Dir.entries(MU.dataDir+"/deployments").each { |deploy|
						next if deploy == "." or deploy == ".." or !Dir.exists?(MU.dataDir+"/deployments/"+deploy) or File.exists?(MU.dataDir+"/deployments/"+deploy+"/.cleanup")
						# XXX should also check for .cleanup on individual nodes
						momma = MU::MommaCat.new(deploy)
						allnodes.merge!(momma.listNodes)
					}
				end
				if !Dir.exists?("#{@nagios_home}/.ssh")
					Dir.mkdir("#{@nagios_home}/.ssh", 0711)
				end
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

				allnodes.each_pair { |nodename, metadata|
					MU::MommaCat.new(metadata['mu_id'])
					if !File.exist?("#{@nagios_home}/.ssh/#{metadata['key_name']}")
						if !File.exist?("#{@myhome}/.ssh/#{metadata['key_name']}")
							MU.log "SSH key #{@myhome}/.ssh/#{metadata['key_name']} referenced by deploy #{metadata['mu_id']} does not exist", MU::ERR, details: metadata
						else
							FileUtils.cp("#{@myhome}/.ssh/#{metadata['key_name']}", "#{@nagios_home}/.ssh/#{metadata['key_name']}")
							File.chown(Etc.getpwnam("nagios").uid, Etc.getpwnam("nagios").gid, "#{@nagios_home}/.ssh/#{metadata['key_name']}")
						end
					end
					if metadata['conf'].nil?
						MU.log "Missing config portion of descriptor for #{nodename}", MU::WARN, details: metadata
						next
					end

					# Prefer a direct route, if that's a choice we have.
					if MU::Cloud::AWS::VPC.haveRouteToInstance?(metadata['instance_id'])
						MU::MommaCat.addHostToSSHConfig(
							nodename,
							metadata['private_ip_address'],
							metadata['private_dns_name'],
							public_dns: metadata['public_dns_name'],
							public_ip: metadata['public_ip_address'],
							user: metadata['conf']['ssh_user'],
							key_name: metadata['key_name'],
							ssh_dir: "#{@nagios_home}/.ssh",
							ssh_conf: "#{@nagios_home}/.ssh/config.tmp",
							ssh_owner: "nagios"
						)
						next
					end

					if !MU.mu_id.nil?
# XXX we need our own exception type for this
						begin
							nat_ssh_key, nat_ssh_user, nat_ssh_host = MU::Cloud::AWS::Server.getNodeSSHProxy(metadata['conf'])
						rescue  Exception => e
							MU::MommaCat.unlockAll
							MU.log e.inspect, MU::ERR, details: e.backtrace
							next
						end
					end
					if !nat_ssh_host.nil? and !nat_ssh_host.empty?
						MU::MommaCat.addHostToSSHConfig(
							nodename,
							metadata['private_ip_address'],
							metadata['private_dns_name'],
							user: metadata['conf']['ssh_user'],
							gateway_ip: nat_ssh_host,
							gateway_user: nat_ssh_user,
							key_name: metadata['key_name'],
							ssh_dir: "#{@nagios_home}/.ssh",
							ssh_conf: "#{@nagios_home}/.ssh/config.tmp",
							ssh_owner: "nagios"
						)
					else
						MU::MommaCat.addHostToSSHConfig(
							nodename,
							metadata['private_ip_address'],
							metadata['private_dns_name'],
							public_dns: metadata['public_dns_name'],
							public_ip: metadata['public_ip_address'],
							user: metadata['conf']['ssh_user'],
							key_name: metadata['key_name'],
							ssh_dir: "#{@nagios_home}/.ssh",
							ssh_conf: "#{@nagios_home}/.ssh/config.tmp",
							ssh_owner: "nagios"
						)
					end
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
							MU.log "Original config of deploy #{MU.mu_id} looks funny. It's probably very old.", MU::WARN
							next
						end
						metadata['mu_id'] = MU.mu_id
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

		# Make sure deployment data is synchronized to/from each Chef node in the
		# currently-loaded deployment.
		# @param updating_node_type [String]: The class of node we're synchronizing, meaning the 'name' field of the server or server_pool resource we're working with.
		# @param saveonly [Boolean]: If true, skip rerunning Chef on nodes.
		def self.syncSiblings(updating_node_type, saveonly = false, triggering_node: nil)
			deployment = MU.mommacat.deployment.dup
			original_config = MU.mommacat.original_config.dup
			environment = MU.mommacat.environment.dup
			ssh_key_name = MU.mommacat.ssh_key_name.dup

			if File.exists?(Etc.getpwuid(Process.uid).dir+"/.chef/knife.rb")
				Chef::Config.from_file(Etc.getpwuid(Process.uid).dir+"/.chef/knife.rb")
			end
			Chef::Config[:environment] = MU.environment

			return if deployment.nil? or deployment['servers'].nil? or original_config.nil? or environment.nil? or ssh_key_name.nil?

			sibling_config = Hash.new
			deployment['servers'].each_pair { |sib_name, sibling_collection|
				['servers', 'server_pools'].each { |server_type|
					if !original_config[server_type].nil?
						original_config[server_type].each { |conf_block|
							if conf_block['name'] == sib_name
								sibling_config = conf_block
								break
							end
						}
					end
				}
				if sibling_config.size == 0
					MU.log "Couldn't find original config for node type #{sib_name}"
				end
				has_no_chef_data = []
				if sibling_collection.is_a?(Hash)
					# fetch Chef data that the nodes have generated
					sibling_collection.each_pair { |nodename, sibling|
						begin
							chef_node = Chef::Node.load(nodename)
						rescue Net::HTTPServerException => e
							# This isn't typically an error condition. Usually happens when
							# we've been called before all nodes have been bootstrapped by
							# Chef, which is routine.
							MU.log "#{nodename} Chef load: #{e.inspect}", MU::DEBUG, details: sibling_collection
							has_no_chef_data << nodename
							next
						end
						# While we're in here, delete references to any retired nodes.
						chef_node.normal['deployment']['servers'].each_pair { |node_class, node_collection|
							deletia_count = 0
							node_collection.each_pair { |deletia_name, deletia_data|
								
								if deployment['servers'][node_class].nil?
									deletia_count = deletia_count + 1
									chef_node.normal['deployment']['servers'].delete(node_class)
								elsif deployment['servers'][node_class][deletia_name].nil?
									deletia_count = deletia_count + 1
									chef_node.normal['deployment']['servers'][node_class].delete(deletia_name)
								end
							}
							if deletia_count > 0
								MU.log "Some sibling nodes were deleted, expunging from #{nodename}"
								chef_node.save
							end
						}
						# Now update this sibling node's node-specific metadata
						node_chef_data = chef_node.normal['deployment']['servers'][sib_name][nodename].dup
						if !node_chef_data.nil? and node_chef_data.size > 0
							MU.log "Merging Chef node data into deployment struct for #{nodename}", MU::DEBUG, details: node_chef_data
							node_chef_data.merge!(deployment['servers'][sib_name][nodename])
							deployment['servers'][sib_name][nodename] = node_chef_data.dup
						end
						other_chef_data = chef_node.normal['deployment'].dup
						['admins', 'firewall_rules', 'vpcs', 'loadbalancers', 'server_pools', 'servers', 'databases'].each { |res_type|
							other_chef_data.delete(res_type)
						}
						MU.log "Merging non-resource deployment struct data for #{nodename}", MU::DEBUG, details: other_chef_data
						deployment.merge!(other_chef_data)
					}
					# save it back to each sibling, and re-run Chef
					sibling_collection.each_pair { |nodename, sibling|
						next if has_no_chef_data.include?(nodename)
						if !updating_node_type.nil? and
								updating_node_type == sib_name and
								sibling_config['sync_siblings']
							MU::Cloud::AWS::Server.saveDeploymentToChef(nodename, deployment)
							next if saveonly or triggering_node == nodename or sibling_collection.size == 1
							MU.log "Re-running Chef on '#{sib_name}' member '#{nodename}'"
							server_conf = sibling_config.dup
							server_conf['mu_name'] = nodename
							server_conf['instance_id'] = sibling['instance_id']
							parent_thread_id = Thread.current.object_id
							Thread.new {
								MU.dupGlobals(parent_thread_id)
								begin
									MU::Cloud::AWS::Server.deploy(
										server_conf,
										deployment,
										environment: environment,
										keypairname: ssh_key_name,
										chef_rerun_only: true
									)
								rescue Exception => e
									MU::MommaCat.unlockAll
#									if !File.exists?(deploy_dir+"/.cleanup."+sibling['instance_id']) and !File.exists?(deploy_dir+"/.cleanup")
									raise e
#									else
#										MU.log "#{sibling['instance_id']} is in mid-cleanup", MU::WARN
#									end
								end
							}
							MU.log "Chef synchronization on '#{sib_name}' member '#{nodename}' complete"
						end
					}
				end
			}
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

		# Check to see whether a given resource name is unique across all
		# deployments on this Mu server. We only enforce this for certain classes
		# of names. If the name in question is available, add it to our cache of
		# said names.  See #{MU::MommaCat.getResourceName}
		# @param name [String]: The name to attempt to allocate.
		# @return [Boolean]: True if allocation was successful.
		def self.allocateUniqueResourceName(name)
			raise MuError, "Cannot call allocateUniqueResourceName without an active deployment" if MU.mu_id.nil?
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
					f.puts name+":"+MU.mu_id
					return true
				ensure
					f.flock(File::LOCK_UN)
				end
			}
		end

		###########################################################################
		###########################################################################
		def self.deploy_dir(mu_id)
			raise MuError, "deploy_dir must get a mu_id if called as class method" if mu_id.nil?
# XXX this will blow up if someone sticks MU in /
			path = File.expand_path(MU.dataDir+"/deployments")
			if !Dir.exist?(path)
				MU.log "Creating #{path}", MU::DEBUG
				Dir.mkdir(path, 0700)
			end
			path = path+"/"+mu_id
			return path
		end
		def self.deploy_exists?(mu_id)
			if mu_id.nil? or mu_id.empty?
				MU.log "Got nil mu_id in MU::MommaCat.deploy_exists?", MU::WARN
				return
			end
			path = File.expand_path(MU.dataDir+"/deployments")
			if !Dir.exists?(path)
				Dir.mkdir(path, 0700)
			end
			deploy_path = File.expand_path(path+"/"+mu_id)
			return Dir.exist?(deploy_path)
		end
		def deploy_dir
			MU::MommaCat.deploy_dir(@mu_id)
		end


		def createDeployKey
			key = OpenSSL::PKey::RSA.generate(4096)
			MU.log "Generated deploy key for #{MU.mu_id}", MU::DEBUG, details: key.public_key.export
			return [key.export, key.public_key.export]
		end

		# Synchronize all in-memory information related to this to deployment to
		# disk.
		def save!(updating_node_type = nil)
			@deploy_struct_semaphore.synchronize {
				MU.log "Saving deployment #{MU.mu_id}", MU::DEBUG

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
					MU::MommaCat.syncSiblings(updating_node_type)
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
		def loadDeploy(deployment_json_only = false)
			@deploy_struct_semaphore.synchronize {
				if File.size?(deploy_dir+"/deployment.json")
					deploy = File.open("#{deploy_dir}/deployment.json", File::RDONLY)
					MU.log "Getting lock to read #{deploy_dir}/deployment.json", MU::DEBUG
					deploy.flock(File::LOCK_EX)
					begin					
						@deployment = JSON.parse(File.read("#{deploy_dir}/deployment.json"))
					rescue JSON::ParserError => e
						raise MuError, "JSON parse failed on #{deploy_dir}/deployment.json\n"+File.read("#{deploy_dir}/deployment.json")
					end
					deploy.flock(File::LOCK_UN)
					deploy.close
					["appname", "environment", "timestamp", "seed", "handle"].each { |var|
						if @deployment[var]
							if var != "handle"	
								MU.setVar(var, @deployment[var].upcase)
							else
								MU.setVar(var, @deployment[var])
							end
						else
							MU.log "Missing global variable #{var} for #{MU.mu_id}", MU::ERR
						end
					}
					return if deployment_json_only
				end
				if File.exist?(deploy_dir+"/private_key")
					@private_key = File.read("#{deploy_dir}/private_key")
					@public_key = File.read("#{deploy_dir}/public_key")
				end
				if File.exist?(deploy_dir+"/basket_of_kittens.json")
					@original_config = JSON.parse(File.read("#{deploy_dir}/basket_of_kittens.json"))
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

