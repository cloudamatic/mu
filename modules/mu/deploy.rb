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

require "net/http"
require "net/smtp"
require 'json'
require 'rexml/document'
require 'simple-password-gen'

module MU
	# The Deploy class is the main interface for resource creation. It is
	# typically invoked from the *mu-deploy* utility. It consumes a configuration
	# parsed by {MU::Config} and generates cloud artifacts accordingly, ordering
	# them per their dependencies and handing off to OS management tools (e.g.
	# Chef) for application-level orchestration.
	class Deploy

		Thread.current.thread_variable_set("name", "main_thread");

		# These also exist as instance variables, but we end up needing versions of
		# them in static contexts too.
		@deploy_semaphore = Mutex.new

		# The name of the application which we're building.
		attr_reader :appname

		# The timestamp at which this deployment was begun
		attr_reader :timestamp

		# The environment into which we're deploying
		attr_reader :environment

		# The MU root directory
		attr_reader :myhome

		# The name of the SSH keypair associated with this deployment
		attr_reader :keypairname

		# The metadata for all resources in this deployment (this is just a shortcut into {MU::MommaCat#deployment})
		attr_reader :deployment

		# The cloud provider's account identifier
		attr_reader :account_number

		# An optional flag to skip instance bootstrapping steps, instead allowing
		# {MU::MommaCat} to do them asynchronously.
		attr_reader :mommacat_boot

		# This flag indicates that cleanup operations should be skipped if a
		# failure occurs.
		attr_reader :nocleanup
		
		# Log information about a resource to our deployment structure, which nodes
		# can then access for orchestration purposes.
		# @param res_type [String]:	The type of cloud resource (server, loadbalancer, etc)
		# @param key [String]: The resource's MU name
		# @param data [Hash]:	Metadata about this resource we wish to save
		# @return [void]
		def notify(res_type, key, data) 
			raise "Called notify without active deployment!" if MU.mommacat.nil?
			MU.mommacat.notify(res_type, key, data)
		end
		# (see #notify)
		def self.notify(res_type, key, data, mu_id: mu_id)
			raise "Called notify without active deployment!" if MU.mommacat.nil?
			MU.mommacat.notify(res_type, key, data)
		end

		# The metadata for all resources in this deployment (this is just a shortcut to {MU::MommaCat#deployment})
		# @!attribute [r]
		def deployment(mu_id: mu_id = MU.mu_id)
			return nil if MU.mommacat.nil?
			MU.mommacat.deployment
		end
		# @!attribute [r]
		# (see #deployment)
		def self.deployment(mu_id: mu_id = MU.mu_id)
			return nil if MU.mommacat.nil?
			MU.mommacat.deployment
		end

		# @param environment [String]: The environment name for this application stack (e.g. "dev" or "prod")
		# @param verbosity [Boolean]: Toggles debug-level log verbosity
		# @param webify_logs [Boolean]: Toggles web-friendly log output
		# @param nocleanup [Boolean]: Toggles whether to skip cleanup of resources if this deployment fails.
		# @param mommacat_boot [Boolean]: Toggles whether to skip full bootstrap of Server resources, leaving them to be groomed by the Momma Cat daemon instead.
		# @param stack_conf [Hash]: A full application stack configuration parsed by {MU::Config}
		def initialize(environment,
									verbosity: verbosity,
									webify_logs: webify_logs,
									nocleanup: nocleanup,
									mommacat_boot: mommacat_boot,
									stack_conf: stack_conf)
			MU.setVar("verbose", verbosity)
			@webify_logs = webify_logs
			@mommacat_boot = mommacat_boot
			@nocleanup = nocleanup
			MU.setLogging(verbosity, webify_logs)

			if stack_conf.nil? or !stack_conf.is_a?(Hash)
				MU.log "Deploy objects require a stack_conf hash", MU::ERR
				exit 1
			end

			@my_threads = Array.new
			@last_sigterm = 0
			@dependency_threads = {}
			@dependency_semaphore = Mutex.new

			@main_config = stack_conf
			@admins = stack_conf["admins"]

			@environment = environment
			time=Time.new
			@appname = stack_conf["appname"]
			@timestamp = time.strftime("%Y%m%d%H").to_s;
			@timestamp.freeze
			@timestart = time.to_s;
			@timestart.freeze


			retries = 0
			begin
				raise "Failed to allocate an unused MU-ID after #{retries} tries!" if retries > 70
				seedsize = 1 + (retries/10).abs
				seed = Password.pronounceable(8).slice(0..seedsize)
				mu_id = @appname.upcase + "-" + @environment.upcase + "-" + @timestamp + "-" + seed.upcase
			end while MU::MommaCat.deploy_exists?(mu_id) or seed == "mu"
			MU.setVar("mu_id", mu_id)
			MU.setVar("appname", @appname.upcase)
			MU.setVar("environment", @environment.upcase)
			MU.setVar("timestamp", @timestamp)
			MU.setVar("seed", seed)
			MU.setVar("handle", MU::MommaCat.generateHandle(seed))

			MU.log "Deployment id: #{MU.appname} \"#{MU.handle}\" (#{MU.mu_id})"

			# Instance variables that are effectively class variables
			@my_instance_id = MU.getAWSMetaData("instance-id")
			@my_az = MU.getAWSMetaData("placement/availability-zone")
	
			@myhome = Dir.home

			@ssh_private_key = nil
			@ssh_public_key = nil
	
			@fromName ='chef-server';

			MU.resource_types.each { |cloudclass|
				if !@main_config[cloudclass.cfg_plural].nil? and @main_config[cloudclass.cfg_plural].size > 0
					setThreadDependencies(@main_config[cloudclass.cfg_plural])
				end
			}

		end
		

		# Generate an EC2 keypair unique to this deployment.  This will be the main 
		# key for each child node we create in this run. If keys have already been
		# generated, return the existing keys instead of creating new ones.
		# @return [Array<String>]: keypairname, ssh_private_key, ssh_public_key
		def createEc2SSHKey
			return [@keypairname, @ssh_private_key, @ssh_public_key] if !@keypairname.nil?
		  keyname="deploy-#{MU.mu_id}"
			keypair = MU.ec2(MU.myRegion).create_key_pair(key_name: keyname)
			@keypairname = keyname
		  @ssh_private_key = keypair.key_material
			MU.log "SSH Key Pair '#{keyname}' fingerprint is #{keypair.key_fingerprint}"
		
		  if !File.directory?("#{@myhome}/.ssh") then
				MU.log "Creating #{@myhome}/.ssh", MU::DEBUG
		    Dir.mkdir("#{@myhome}/.ssh", 0700)
		  end
		
		  # Plop this private key into our local SSH key stash
			MU.log "Depositing key '#{keyname}' into #{@myhome}/.ssh/#{keyname}", MU::DEBUG
		  ssh_keyfile = File.new("#{@myhome}/.ssh/#{keyname}", File::CREAT|File::TRUNC|File::RDWR, 0600)
		  ssh_keyfile.puts @ssh_private_key
		  ssh_keyfile.close

			# Drag out the public key half of this
			@ssh_public_key = %x{/usr/bin/ssh-keygen -y -f #{@myhome}/.ssh/#{keyname}}
			@ssh_public_key.chomp!

			# Replicate this key in all regions
			MU::Config.listRegions.each { |region|
				next if region == MU.myRegion
				MU.log "Replicating #{keyname} to #{region}", MU::DEBUG, details: @ssh_public_key
				MU.ec2(region).import_key_pair(
					key_name: @keypairname,
					public_key_material: @ssh_public_key
				)
			}

# XXX This library code would be nicer... except it can't do PKCS8.
#			foo = OpenSSL::PKey::RSA.new(@ssh_private_key)
#			bar = foo.public_key

			sleep 3
		  return [keyname, keypair.key_material, @ssh_public_key]
		end
		
		# Activate this deployment, instantiating all resources, orchestrating them,
		# and saving metadata about them.
		def run
			Signal.trap("INT") do
				die = true if (Time.now.to_i - @last_sigterm) < 5
				if !die
					puts "------------------------------"
					puts "Thread and lock debugging data"
					puts "------------------------------"
					puts "Open flock() locks:"
					pp MU::MommaCat.locks
					puts "------------------------------"
				end
			  Thread.list.each do |t|
					next if !t.status # skip threads that've been cleanly terminated
					if die
						if t.object_id != Thread.current.object_id and t.thread_variable_get("name") != "main_thread"
					    t.kill
						end
					else
						thread_name = t.thread_variable_get("name")
						puts "Thread #{thread_name} (#{t.object_id}): #{t.inspect} #{t.status}"
						t.thread_variables.each { |tvar|
							puts "#{tvar} = #{t.thread_variable_get(tvar)}"
						}
						pp t.backtrace
						if !@dependency_threads[thread_name].nil?
							puts ""
							puts "Waiting on #{@dependency_threads[thread_name]}"
							Thread.list.each { |parent|
								parent_name = parent.thread_variable_get("name")
								if @dependency_threads[thread_name].include?(parent_name)
									puts "\t#{parent_name} (#{parent.object_id}): #{parent.inspect} #{parent.status}"
									parent.thread_variables.each { |tvar|
										puts "\t#{tvar} = #{parent.thread_variable_get(tvar)}"
									}
								end
							}
						end
						puts "------------------------------"
						t.run
					end
			  end
				if !die
					puts "Received SIGINT, hit ctrl-C again within five seconds to kill this deployment."
				else
					raise "Terminated by user"
				end
				@last_sigterm = Time.now.to_i
			end

			begin
				keyname, ssh_private_key, ssh_public_key = createEc2SSHKey

				metadata = {
					"appname" => @appname,
					"timestamp" => @timestamp,
					"environment" => @environment,
					"seed" => MU.seed,
					"deployment_start_time" => @timestart,
					"chef_user" => MU.chef_user
				}
				mommacat = MU::MommaCat.new(
					MU.mu_id,
					create: true,
					config: @main_config,
					verbose: MU.verbose,
					ssh_key_name: keyname,
					ssh_private_key: ssh_private_key,
					ssh_public_key: ssh_public_key,
					deployment_data: metadata
				)
				MU.setVar("mommacat", mommacat)

				@admins.each { |admin|
					notify("admins", admin['name'], admin)
				}

				@deploy_semaphore = Mutex.new

				parent_thread_id = Thread.current.object_id

				# Kick off threads to create each of our new servers.
		    @my_threads << Thread.new {
					MU.dupGlobals(parent_thread_id)
					Thread.current.thread_variable_set("name", "mu_create_container")
					MU.resource_types.each { |cloudclass|
						if !@main_config[cloudclass.cfg_plural].nil? and
						 		@main_config[cloudclass.cfg_plural].size > 0 and
								cloudclass.instance_methods(false).include?(:create)
							createResources(@main_config[cloudclass.cfg_plural], "create")
						end
					}
				}

				# Some resources have a "deploy" phase too
		    @my_threads << Thread.new {
					MU.dupGlobals(parent_thread_id)
					Thread.current.thread_variable_set("name", "mu_deploy_container")
					MU.resource_types.each { |cloudclass|
						if !@main_config[cloudclass.cfg_plural].nil? and
						 		@main_config[cloudclass.cfg_plural].size > 0 and
								cloudclass.instance_methods(false).include?(:deploy)
							createResources(@main_config[cloudclass.cfg_plural], "deploy")
						end
					}
				}

			  # Poke child threads to make sure they're awake
			  @my_threads.each do |t|
					t.run if t.alive?
			  end

				sleep 5
			  
			  # Reap child threads.
			  @my_threads.each do |t|
			    t.join
			  end
			rescue Exception => e

			  @my_threads.each do |t|
					if t.object_id != Thread.current.object_id and t.thread_variable_get("name") != "main_thread"
						MU::MommaCat.unlockAll
				    t.kill
					end
			  end

				# If it was a regular old exit, we assume something deeper in already
				# handled logging and cleanup for us, and just quietly go away.
				if e.class.to_s != "SystemExit"
					MU.log e.inspect, MU::ERR, details: e.backtrace
					if !@nocleanup
						MU::Cleanup.run(MU.mu_id, true, false, true, mommacat: mommacat)
					end
					MU.log e.inspect, MU::ERR
				end

			  exit 1
			end
			
			deployment["deployment_end_time"]=Time.new.strftime("%I:%M %p on %A, %b %d, %Y").to_s;
			MU::MommaCat.syncMonitoringConfig	

			# Send notifications
			sendMail
			MU.log "Deployment complete", details: deployment

		end
	
		private

		def sendMail()
		
		  $str = JSON.pretty_generate(deployment)

			admin_addrs = @admins.map { |admin|
				admin['name']+" <"+admin['email']+">"
			}

		  @admins.each do |data|
		
		    message = <<MESSAGE_END
From: #{MU.handle} <#{@fromName}>
To:  #{admin_addrs.join(", ")}>
MIME-Version: 1.0
Content-type: text/html
Subject: Mu deployment #{MU.appname} \"#{MU.handle}\" (#{MU.mu_id}) succesfully completed
		
<br>
<pre>#{$str}</pre>
MESSAGE_END
		    Net::SMTP.start('localhost') do |smtp|
		      smtp.send_message message, @fromName, data["email"]
		    end
		  end
		end  
		

		#########################################################################
		#########################################################################
		def waitOnThreadDependencies(dependent)
			if @dependency_threads[dependent].nil?
				MU.log "I don't see any dependencies for #{dependent}, moving on", MU::DEBUG
				return
			else
				MU.log "#{dependent} checking/waiting for parent threads...", MU::DEBUG, details: @dependency_threads[dependent]
			end

			retries = 0
	    @dependency_threads[dependent].each { |dependent_thread|
				found = false
				@my_threads.each { |parent_thread|
					parent = parent_thread.thread_variable_get("name");
					if parent == dependent_thread
						found = true
						Thread.current.thread_variable_set("waiting_for", parent)
						parent_thread.join
						Thread.current.thread_variable_set("waiting_for", nil)
						MU.log "Thread #{parent} completed, thread #{dependent} proceeding", MU::DEBUG, details: @dependency_threads[dependent]
					end
				}
				# This vile hack brought to you by parent threads spawning after things
				# that depend on them. We're working around the slight race condition
				# that results. If the parent threads never show up, though, we have
				# a more serious problem.
				if !found and retries < 5
					sleep 5
					retries = retries + 1
					redo
				end
				if retries >= 5
					MU.log "#{dependent} tried five times but never saw #{dependent_thread} in live thread list...", MU::ERR, details: @my_threads
					raise "#{dependent} tried five times but never saw #{dependent_thread} in live thread list..."
				end
			}
		end

		
		#########################################################################
		# Helper for setThreadDependencies
		#########################################################################
		def addDependentThread(parent, child)
			@dependency_semaphore.synchronize {
				@dependency_threads[child] = Array.new if !@dependency_threads[child]
				@dependency_threads[child] << parent
				MU.log "Thread #{child} will wait on #{parent}", MU::DEBUG, details: @dependency_threads[child]
			}
		end

		#########################################################################
		# Tell a service's deploy (and optionally, create) thread to wait on its
		# dependent service's create (and optionally, deploy) threads to finish.
		# XXX This nomenclature is unreasonably confusing.
		#########################################################################
		def setThreadDependencies(services)
		  if services.nil? or services.size < 1
#				MU.log "Got nil service list in setThreadDependencies for called from #{caller_locations(1,1)[0].label}", MU::DEBUG
				return
			end

		  services.each { |resource|
				res_type = resource["#MU_CLASS"].name
		    name = res_type+"_"+resource["name"]

				# All resources wait to "deploy" until after their own "create" thread
				# finishes, and also on the main thread which spawns them (so all
				# siblings will exist for dependency checking before we start).
		    @dependency_threads["#{name}_create"]=["mu_create_container"]
		    @dependency_threads["#{name}_deploy"]=["#{name}_create", "mu_deploy_container"]

				MU.log "Setting dependencies for #{name}", MU::DEBUG
				if resource["dependencies"] != nil then
				  resource["dependencies"].each { |dependency|
						parent_class = MU.configType2ObjectType(dependency["type"])

						parent_type = parent_class.name
						parent = parent_type+"_"+dependency["name"]+"_create"
						addDependentThread(parent, "#{name}_deploy")
						if (parent_class.deps_wait_on_my_creation and parent_type != res_type) or resource["#MU_CLASS"].waits_on_parent_completion or dependency['phase'] == "create"
							addDependentThread(parent, "#{name}_create")
						end
						if (dependency['phase'] == "deploy" or resource["#MU_CLASS"].waits_on_parent_completion) and parent_class.instance_methods(false).include?(:deploy)
							parent = parent_type+"_"+dependency["name"]+"_deploy"
							addDependentThread(parent, "#{name}_deploy")
							if (parent_class.deps_wait_on_my_creation and parent_type != res_type) or resource["#MU_CLASS"].waits_on_parent_completion or dependency['phase'] == "deploy"
								addDependentThread(parent, "#{name}_create")
							end
						end
					}
				end
			}
		end

		#########################################################################
		# Kick off a thread to create a resource. 
		#########################################################################
		def createResources(services, mode="create")
			return if services.nil?

			parent_thread_id = Thread.current.object_id
		  services.each do |service|
		    @my_threads << Thread.new(service) { |myservice|
					MU.dupGlobals(parent_thread_id)
					threadname = service["#MU_CLASS"].name+"_"+myservice["name"]+"_#{mode}"
		      Thread.current.thread_variable_set("name", threadname)
		      Thread.abort_on_exception = true
					waitOnThreadDependencies(threadname)

					if service["#MU_CLASS"].instance_methods(false).include?(:deploy)
						if mode == "create"
							MU::MommaCat.lock(service["#MU_CLASS"].name+"_"+myservice["name"]+"-dependencies")
						elsif mode == "deploy"
							MU::MommaCat.unlock(service["#MU_CLASS"].name+"_"+myservice["name"]+"-dependencies")
						end
					end

					MU.log "Launching thread #{threadname}", MU::DEBUG
					begin
						if service['#MUOBJECT'].nil?
							service['#MUOBJECT'] = service["#MU_CLASS"].new(self, myservice)
						end
						run_this_method = service['#MUOBJECT'].method(mode)
					rescue Exception => e
						MU.log "Error invoking #{service["#MU_CLASS"]}.#{mode} for #{myservice['name']} (#{e.message})", MU::ERR
						MU::MommaCat.unlockAll
						raise e
					end
					begin
						MU.log "Running #{service['#MUOBJECT']}.#{mode}", MU::DEBUG
						myservice = run_this_method.call
					rescue Exception => e
						MU.log e.inspect, MU::ERR, details: e.backtrace
						MU::MommaCat.unlockAll
						@my_threads.each do |t|
							if t.object_id != Thread.current.object_id and t.thread_variable_get("name") != "main_thread"
						    t.kill
							end
					  end
						if !@nocleanup
							MU::Cleanup.run(MU.mu_id, true, false, true)
						end
						MU.log e.inspect, MU::ERR
						exit 1
					end
				}
		  end
		end

	end #class
end #module
