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
	# Plugins under this namespace serve as interfaces to cloud providers and
	# other provisioning layers.
	class Cloud

		class MuCloudResourceNotImplemented < StandardError; end

		generic_class_methods = [:find, :cleanup]
		generic_instance_methods = [:create, :notify, :mu_name, :cloud_id]

		# Initialize empty classes for each of these. We'll fill them with code
		# later; we're doing this here because otherwise the parser yells about
		# missing classes, even though they're created at runtime.
		class Collection; end
		class Database; end
		class DNSZone; end
		class FirewallRule; end
		class LoadBalancer; end
		class Server; end
		class ServerPool; end
		class VPC; end
		# The types of cloud resources we can create, as class objects. Include
		# methods a class implementing this resource type must support to be
		# considered valid.
		@@resource_types = {
			:Collection => {
				:has_multiples => false,
				:cfg_name => "collection",
				:cfg_plural => "collections",
				:interface => self.const_get("Collection"),
				:deps_wait_on_my_creation => true,
				:waits_on_parent_completion => false,
				:class => generic_class_methods,
				:instance => generic_instance_methods
			},
			:Database => {
				:has_multiples => false,
				:cfg_name => "database",
				:cfg_plural => "databases",
				:interface => self.const_get("Database"),
				:deps_wait_on_my_creation => true,
				:waits_on_parent_completion => false,
				:class => generic_class_methods,
				:instance => generic_instance_methods + [:groom, :allowHost]
			},
			:DNSZone => {
				:has_multiples => false,
				:cfg_name => "dnszone",
				:cfg_plural => "dnszones",
				:interface => self.const_get("DNSZone"),
				:deps_wait_on_my_creation => true,
				:waits_on_parent_completion => false,
				:class => generic_class_methods + [:genericMuDNSEntry],
				:instance => generic_instance_methods
			},
			:FirewallRule => {
				:has_multiples => false,
				:cfg_name => "firewall_rule",
				:cfg_plural => "firewall_rules",
				:interface => self.const_get("FirewallRule"),
				:deps_wait_on_my_creation => true,
				:waits_on_parent_completion => false,
				:class => generic_class_methods,
				:instance => generic_instance_methods + [:groom, :addRule]
			},
			:LoadBalancer => {
				:has_multiples => false,
				:cfg_name => "loadbalancer",
				:cfg_plural => "loadbalancers",
				:interface => self.const_get("LoadBalancer"),
				:deps_wait_on_my_creation => true,
				:waits_on_parent_completion => false,
				:class => generic_class_methods,
				:instance => generic_instance_methods
			},
			:Server => {
				:has_multiples => true,
				:cfg_name => "server",
				:cfg_plural => "servers",
				:interface => self.const_get("Server"),
				:deps_wait_on_my_creation => false,
				:waits_on_parent_completion => false,
				:class => generic_class_methods,
				:instance => generic_instance_methods + [:groom, :postBoot, :getSSHConfig, :canonicalIP, :getWindowsAdminPassword]
			},
			:ServerPool => {
				:has_multiples => false,
				:cfg_name => "server_pool",
				:cfg_plural => "server_pools",
				:interface => self.const_get("ServerPool"),
				:deps_wait_on_my_creation => false,
				:waits_on_parent_completion => true,
				:class => generic_class_methods,
				:instance => generic_instance_methods
			},
			:VPC => {
				:has_multiples => false,
				:cfg_name => "vpc",
				:cfg_plural => "vpcs",
				:interface => self.const_get("VPC"),
				:deps_wait_on_my_creation => true,
				:waits_on_parent_completion => false,
				:class => generic_class_methods,# + [:isSubnetPrivate?, :getDefaultRoute],
				:instance => generic_instance_methods + [:groom, :subnets, :getSubnet]
			},
		}.freeze


		# A list of supported cloud resource types as Mu classes
		def self.resource_types ; @@resource_types end

		# List of known/supported Cloud providers
		def self.supportedClouds
			["AWS", "Docker"]
		end

		# Load the container class for each cloud we know about, and inject autoload
		# code for each of its supported resource type classes.
		MU::Cloud.supportedClouds.each { |cloud|
			require "mu/clouds/#{cloud.downcase}"
		}

		# Given a cloud layer and resource type, return the class which implements it.
		# @param cloud [String]: The Cloud layer
		# @param type [String]: The resource type. Can be the full class name, symbolic name, or Basket of Kittens configuration shorthand for the resource type.
		# @return [Class]: The cloud-specific class implementing this resource
		def self.loadCloudType(cloud, type)
			raise MuError, "cloud argument to MU::Cloud.loadCloudType cannot be nil" if cloud.nil?
			# If we've been asked to resolve this object, that means we plan to use it,
			# so go ahead and load it.
			cfg_name = nil
			@@resource_types.each_pair { |name, cloudclass|
				if name == type.to_sym or
					 cloudclass[:cfg_name] == type or
					 cloudclass[:cfg_plural] == type or
					 Object.const_get("MU").const_get("Cloud").const_get(name) == type
					cfg_name = cloudclass[:cfg_name]
					type = name
					break
				end
			}
			if cfg_name.nil?
				puts caller
				raise MuError, "Can't find a cloud resource type named '#{type}'"
			end
			if !File.size?(MU.myRoot+"/modules/mu/clouds/#{cloud.downcase}.rb")
				raise MuError, "Requested to use unsupported provisioning layer #{cloud}"
			end
			begin
				require "mu/clouds/#{cloud.downcase}/#{cfg_name}"
			rescue LoadError => e
				raise MuCloudResourceNotImplemented
			end
			begin
				myclass = Object.const_get("MU").const_get("Cloud").const_get(cloud).const_get(type)
				# XXX also test whether methods take the expected arguments
				@@resource_types[type.to_sym][:class].each { |class_method|
					begin
						# XXX this is a hack, we really just want to check for existence
						myclass.public_class_method(class_method)				
					rescue NameError
						raise MuError, "MU::Cloud::#{cloud}::#{type} has not implemented required class method #{class_method}"
					end
				}
				@@resource_types[type.to_sym][:instance].each { |instance_method|
					if !myclass.public_instance_methods.include?(instance_method)
						raise MuError, "MU::Cloud::#{cloud}::#{type} has not implemented required instance method #{instance_method}"
					end
				}

				return myclass
			rescue NameError => e
				raise MuError, "The '#{type}' resource is not supported in cloud #{cloud} (tried MU::#{cloud}::#{type})", e.backtrace
			end
		end

		MU::Cloud.supportedClouds.each { |cloud|
			Object.const_get("MU").const_get("Cloud").const_get(cloud).class_eval {

				# Automatically load supported cloud resource classes when they're
				# referenced.
				def self.const_missing(symbol)
					if MU::Cloud.resource_types.has_key?(symbol.to_sym)
						return MU::Cloud.loadCloudType(name.sub(/.*?::([^:]+)$/, '\1'), symbol)
					else
						raise MuCloudResourceNotImplemented, "No such cloud resource #{name}:#{symbol}"
					end
				end
			}
		}


		@@resource_types.each_pair { |name, attrs|
			Object.const_get("MU").const_get("Cloud").const_get(name).class_eval {
				attr_reader :config
				attr_reader :cloud
				attr_reader :environment
				attr_reader :cloudclass
				attr_reader :cloudobj
				attr_reader :deploy_id
				def self.shortname
					name.sub(/.*?::([^:]+)$/, '\1')
				end

				def initialize(mommacat: nil,
											 mu_name: nil,
											 cloud_id: nil,
											 kitten_cfg: kitten_cfg)
					raise MuError, "Cannot invoke Cloud objects without a configuration" if kitten_cfg.nil?
					@deploy = mommacat
					@config = kitten_cfg
					if !@deploy.nil?
						@deploy_id = @deploy.deploy_id
						MU.log "Initializing an instance of #{self.class.name} in #{@deploy_id} #{mu_name}", MU::DEBUG, details: kitten_cfg
					else
						MU.log "Initializing an instance of #{self.class.name}", MU::DEBUG, details: kitten_cfg
					end
					if !kitten_cfg.has_key?("cloud")
						kitten_cfg['cloud'] = MU::Config.defaultCloud
					end
					@cloud = kitten_cfg['cloud']
					@environment = kitten_cfg['environment']
					@cloudclass = MU::Cloud.loadCloudType(@cloud, self.class.shortname)
# XXX require subclass to provide attr_readers of @config and @deploy
					# If we're called with a cloud_id, we're probably putting together
					# a dummy resource handle for some kind of foreign resource.
					if !cloud_id.nil?
						@cloudobj = @cloudclass.new(mommacat: mommacat, cloud_id: cloud_id, kitten_cfg: kitten_cfg)
					elsif mu_name.nil?
						@cloudobj = @cloudclass.new(mommacat: mommacat, kitten_cfg: kitten_cfg)
						if !@cloudobj.nil?
							@deploy.kittens[self.class.cfg_plural] = {} if !@deploy.kittens.has_key?(self.class.cfg_plural)
							@deploy.kittens[self.class.cfg_plural][@cloudobj.mu_name] = self
						end
					else
						@cloudobj = @cloudclass.new(mommacat: mommacat, kitten_cfg: kitten_cfg, mu_name: mu_name)
						# prepopulate the describe() cache
						@cloudobj.describe(cloud_id: cloud_id)
					end
				end

				# Retrieve all of the known metadata for this resource.
				# @param cloud_id [String]: The cloud platform's identifier for the resource we're describing. Makes lookups more efficient.
				# @param update_cache [Boolean]: Ignore cached data if we have any, instead reconsituting from original sources.
				# @return [Array<Hash>]: mu_name, config, deploydata, cloud_descriptor
				def describe(cloud_id: nil, update_cache: false)
					if cloud_id.nil? and !@cloudobj.nil?
						@cloud_id = @cloudobj.cloud_id
					end
					res_type = self.class.cfg_plural
					res_name = @config['name']
					if !@deploy.deployment.nil? and !@deploy.deployment[res_type].nil? and !@deploy.deployment[res_type][res_name].nil?
						deploydata = @deploy.deployment[res_type][res_name]
					elsif update_cache or @deploydata.nil?
						deploydata = MU::MommaCat.getResourceMetadata(res_type, name: res_name, deploy_id: @deploy.deploy_id, mu_name: @mu_name)
					end
					# XXX :has_multiples is what to actually check here
					if !@mu_name.nil? and deploydata.is_a?(Hash) and deploydata.has_key?(@mu_name)
						@deploydata = deploydata[@mu_name]
					else
						@deploydata = deploydata
					end
					if @cloud_id.nil? and @deploydata.is_a?(Hash)
						if @mu_name.nil? and @deploydata.has_key?('#MU_NAME')
							@mu_name = @deploydata['#MU_NAME']
						end
						if @deploydata.has_key?('cloud_id')
							@cloud_id = @deploydata['cloud_id']
						else
							# XXX temp hack to catch old Amazon-style identifiers. Remove this
							# before supporting any other cloud layers, otherwise name
							# collision is possible.
							["vpc_id", "instance_id", "awsname", "identifier", "group_id", "id"].each { |identifier|
								if @deploydata.has_key?(identifier)
									@cloud_id = @deploydata[identifier]
									if @mu_name.nil? and (identifier == "awsname" or identifier == "identifier" or identifier == "group_id")
										@mu_name = @deploydata[identifier]
									end
									break
								end
							}
						end
					end
					if update_cache or @cloud_desc.nil?
						@cloud_desc = self.class.find(region: @config['region'], cloud_id: @cloud_id)
					end

					return [@mu_name, @config, @deploydata, @cloud_desc]
				end

				def self.cfg_plural
					MU::Cloud.resource_types[shortname.to_sym][:cfg_plural]
				end
				def self.cfg_name
					MU::Cloud.resource_types[shortname.to_sym][:cfg_name]
				end
				def self.waits_on_parent_completion
					MU::Cloud.resource_types[shortname.to_sym][:waits_on_parent_completion]
				end
				def self.deps_wait_on_my_creation
					MU::Cloud.resource_types[shortname.to_sym][:deps_wait_on_my_creation]
				end

				def self.find(*flags)
					MU::Cloud.supportedClouds.each { |cloud|
						begin
							cloudclass = MU::Cloud.loadCloudType(cloud, shortname)
							found = cloudclass.find(flags.first)
							return found if !found.nil? # XXX actually, we should merge all results
						rescue MuCloudResourceNotImplemented
						end
						return nil
					}
				end

# XXX This method should only exist for MU::Cloud::VPC
				def self.haveRouteToInstance?(*flags)
# XXX have this switch on a global config for where Mu puts its DNS
					begin
						cloudclass = MU::Cloud.loadCloudType(MU::Config.defaultCloud, "VPC")
					rescue MuCloudResourceNotImplemented
						return true
					end
					cloudclass.haveRouteToInstance?(flags.first)
				end

# XXX This method should only exist for MU::Cloud::DNSZone
				def self.genericMuDNSEntry(*flags)
# XXX have this switch on a global config for where Mu puts its DNS
					cloudclass = MU::Cloud.loadCloudType(MU::Config.defaultCloud, "DNSZone")
					cloudclass.genericMuDNSEntry(flags.first)
				end

# XXX This method should only exist for MU::Cloud::Server
				# @param max_retries [Integer]: Number of connection attempts to make before giving up
				# @param retry_interval [Integer]: Number of seconds to wait between connection attempts
				# @return [Net::SSH::Connection::Session]
				def getSSHSession(max_retries = 5, retry_interval = 30)
					ssh_keydir = Etc.getpwuid(Process.uid).dir+"/.ssh"
					nat_ssh_key, nat_ssh_user, nat_ssh_host, canonical_ip, ssh_user, ssh_key_name = getSSHConfig
					session = nil
					retries = 0
					begin
						if !nat_ssh_host.nil?
							proxy_cmd = "ssh -q -o StrictHostKeyChecking=no -W %h:%p #{nat_ssh_user}@#{nat_ssh_host}"
							MU.log "Attempting SSH to #{@config['mu_name']} (#{canonical_ip}) as #{ssh_user} with key #{@deploy.ssh_key_name} using proxy '#{proxy_cmd}'" if retries == 0
							proxy = Net::SSH::Proxy::Command.new(proxy_cmd)
							session = Net::SSH.start(
								canonical_ip,
								ssh_user,
								:config => false, 
								:keys_only => true,
								:keys => [ssh_keydir+"/"+nat_ssh_key, ssh_keydir+"/"+@deploy.ssh_key_name],
								:paranoid => false,
		#						:verbose => :info,
								:port => 22,
								:auth_methods => ['publickey'],
								:proxy => proxy
							)
						else
							MU.log "Attempting SSH to #{canonical_ip} as #{ssh_user} with key #{ssh_keydir}/#{@deploy.ssh_key_name}" if retries == 0
							session = Net::SSH.start(
								canonical_ip,
								ssh_user,
								:config => false, 
								:keys_only => true,
								:keys => [ssh_keydir+"/"+@deploy.ssh_key_name],
								:paranoid => false,
		#						:verbose => :info,
								:port => 22,
								:auth_methods => ['publickey']
							)
				    end
					  rescue Net::SSH::HostKeyMismatch => e
					    MU.log("Remembering new key: #{e.fingerprint}")
					    e.remember_host!
							session.close
					    retry
						rescue SystemCallError, Timeout::Error, Errno::EHOSTUNREACH, Net::SSH::Proxy::ConnectError, SocketError, Net::SSH::Disconnect, Net::SSH::AuthenticationFailed, IOError => e
							begin
								session.close if !session.nil?
							rescue Net::SSH::Disconnect, IOError => e
								if %w{win2k12r2 win2k12 windows}.include?(@config['platform'])
									MU.log "Windows has probably closed the ssh session before we could. Waiting before trying again", MU::NOTICE
								else
									MU.log "ssh session was closed unexpectedly, waiting before trying again", MU::NOTICE
								end
								sleep 10
							end

							if retries < max_retries
								retries = retries + 1
								msg = "ssh #{ssh_user}@#{@config['mu_name']}: #{e.message}, waiting #{retry_interval}s (attempt #{retries}/#{max_retries})"
								if retries == 1 or (retries/max_retries <= 0.5 and (retries % 3) == 0)
									MU.log msg, MU::NOTICE
								elsif retries/max_retries > 0.5
									MU.log msg, MU::WARN, details: e.inspect
								end
								sleep retry_interval
								retry
							else
								raise MuError, "#{@config['mu_name']}: #{e.inspect} trying to connect with SSH, max_retries exceeded", e.backtrace
							end
						end
					return session
				end

				def self.cleanup(*flags)
					MU::Cloud.supportedClouds.each { |cloud|
						begin
							cloudclass = MU::Cloud.loadCloudType(cloud, shortname)
							MU.log "Invoking #{cloudclass}.cleanup", MU::DEBUG, details: flags
							cloudclass.cleanup(flags.first)
						rescue MuCloudResourceNotImplemented
						end
					}
				end

				# Wrap the instance methods that this cloud resource type has to
				# implement.
				MU::Cloud.resource_types[name.to_sym][:instance].each { |method|
					define_method method do |*args|
						return nil if @cloudobj.nil?
						MU.log "Invoking #{@cloudobj}.#{method}", MU::DEBUG
						if method != :describe
							# make sure the stuff this populates is ready
							@cloudobj.describe
						end
						retval = nil
						if !args.nil? and args.size > 0
							retval = @cloudobj.method(method).call(args.first)
						else
							retval = @cloudobj.method(method).call
						end
						if method == :create or method == :groom or method == :postBoot
							@cloudobj.method(:notify).call
							deploydata = @cloudobj.method(:notify).call
							deploydata['cloud_id'] = @cloudobj.cloud_id if !@cloudobj.cloud_id.nil?
							deploydata['mu_name'] = @cloudobj.mu_name if !@cloudobj.mu_name.nil?
							@deploy.notify(self.class.cfg_plural, @config['name'], deploydata)
						elsif method == :notify
							retval['cloud_id'] = @cloudobj.cloud_id if !@cloudobj.cloud_id.nil?
							retval['mu_name'] = @cloudobj.mu_name if !@cloudobj.mu_name.nil?
							@deploy.notify(self.class.cfg_plural, @config['name'], retval)
						end
						retval
					end
				} # end instance method list
			} # end dynamic class generation block
		} # end resource type iteration

	end

end
