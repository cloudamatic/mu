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

		class MuCloudResourceNotImplemented < StandardError
		end

		generic_class_methods = [:find, :cleanup]
		generic_instance_methods = [:create, :deps_wait_on_my_creation, :waits_on_parent_completion]

		# The types of cloud resources we can create, as class objects. Include
		# methods a class implementing this resource type must support to be
		# considered valid.
		@@resource_types = {
			:Collection => {
				:cfg_name => "collection",
				:cfg_plural => "collections",
				:class => generic_class_methods,
				:instance => generic_instance_methods
			},
			:Database => {
				:cfg_name => "database",
				:cfg_plural => "databases",
				:class => generic_class_methods,
				:instance => generic_instance_methods + [:groom]
			},
			:DNSZone => {
				:cfg_name => "dnszone",
				:cfg_plural => "dnszones",
				:class => generic_class_methods,
				:instance => generic_instance_methods
			},
			:FirewallRule => {
				:cfg_name => "firewall_rule",
				:cfg_plural => "firewall_rules",
				:class => generic_class_methods,
				:instance => generic_instance_methods + [:groom]
			},
			:LoadBalancer => {
				:cfg_name => "loadbalancer",
				:cfg_plural => "loadbalancers",
				:class => generic_class_methods,
				:instance => generic_instance_methods
			},
			:Server => {
				:cfg_name => "server",
				:cfg_plural => "servers",
				:class => generic_class_methods + [:postBoot],
				:instance => generic_instance_methods + [:groom]
			},
			:ServerPool => {
				:cfg_name => "server_pool",
				:cfg_plural => "server_pools",
				:class => generic_class_methods,
				:instance => generic_instance_methods
			},
			:VPC => {
				:cfg_name => "vpc",
				:cfg_plural => "vpcs",
				:class => generic_class_methods,
				:instance => generic_instance_methods + [:groom]
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
		# @param type [String]: The resource type
		# @return [Class]: The cloud-specific class implementing this resource
		def self.artifact(cloud = MU::Config.defaultCloud, type)
			raise MuError, "cloud argument to MU::Cloud.artifact cannot be nil" if cloud.nil?
			# If we've been asked to resolve this object, that means we plan to use it,
			# so go ahead and load it.
			cfg_name = nil
			@@resource_types.each_pair { |name, cloudclass|
				if name == type.to_sym or
					 cloudclass[:cfg_name] == type or
					 cloudclass[:cfg_plural] == type
					cfg_name = cloudclass[:cfg_name]
					type = name
					break
				end
			}
			if cfg_name.nil?
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

		@@resource_types.each_pair { |name, attrs|
			resource_container = Class.new(MU::Cloud) {
				attr_reader :config
				attr_reader :cloud
				attr_reader :environment
				attr_reader :deploydata
				attr_reader :cloudclass
				attr_reader :cloudobj

				def initialize(mommacat: mommacat = nil,
											 kitten_cfg: kitten_cfg)
					@config = kitten_cfg
					@cloud = kitten_cfg['cloud']
					@environment = kitten_cfg['environment']
					@deploydata = mommacat.deployment
					@cloudclass = MU::Cloud.artifact(@cloud, self.class.name)
					@cloudobj = @cloudclass.new(mommacat: mommacat, kitten_cfg: kitten_cfg)
				end

				def self.cfg_plural
					MU::Cloud.resource_types[name.to_sym][:cfg_plural]
				end
				def self.cfg_name
					MU::Cloud.resource_types[name.to_sym][:cfg_name]
				end

				# XXX figure out how to do args and return values here
				def self.find
					MU::Cloud.supportedClouds.each { |cloud|
						cloudclass = MU::Cloud.artifact(cloud, name)
						cloudclass.find
					}
				end

				# XXX figure out how to do args and return values here
				def self.cleanup(noop: false,
					               ignoremaster: false,
												 region: MU.myRegion)
					MU::Cloud.supportedClouds.each { |cloud|
						begin
							cloudclass = MU::Cloud.artifact(cloud, name)
							MU.log "Invoking #{cloudclass}.cleanup in #{region}", MU::DEBUG
							cloudclass.cleanup(noop: noop, ignoremaster: ignoremaster, region: region)
						rescue MuCloudResourceNotImplemented
						end
					}
				end

				# Wrap the instance methods that this cloud resource type has to
				# implement.
				MU::Cloud.resource_types[name.to_sym][:instance].each { |method|
					define_method method do
						MU.log "Invoking #{@cloudobj}.#{method}", MU::DEBUG
						@cloudobj.method(method).call
					end
				}

			}
			Object.const_set name, resource_container
		}

	end

end
