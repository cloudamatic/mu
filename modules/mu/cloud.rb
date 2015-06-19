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
		generic_instance_methods = [:create, :deps_wait_on_my_creation, :waits_on_parent_completion, :notify]

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
				:class => generic_class_methods,
				:instance => generic_instance_methods
			},
			:Database => {
				:has_multiples => false,
				:cfg_name => "database",
				:cfg_plural => "databases",
				:interface => self.const_get("Database"),
				:class => generic_class_methods,
				:instance => generic_instance_methods + [:groom]
			},
			:DNSZone => {
				:has_multiples => false,
				:cfg_name => "dnszone",
				:cfg_plural => "dnszones",
				:interface => self.const_get("DNSZone"),
				:class => generic_class_methods + [:genericMuDNSEntry],
				:instance => generic_instance_methods
			},
			:FirewallRule => {
				:has_multiples => false,
				:cfg_name => "firewall_rule",
				:cfg_plural => "firewall_rules",
				:interface => self.const_get("FirewallRule"),
				:class => generic_class_methods,
				:instance => generic_instance_methods + [:groom]
			},
			:LoadBalancer => {
				:has_multiples => false,
				:cfg_name => "loadbalancer",
				:cfg_plural => "loadbalancers",
				:interface => self.const_get("LoadBalancer"),
				:class => generic_class_methods,
				:instance => generic_instance_methods
			},
			:Server => {
				:has_multiples => true,
				:cfg_name => "server",
				:cfg_plural => "servers",
				:interface => self.const_get("Server"),
				:class => generic_class_methods,
				:instance => generic_instance_methods + [:groom, :postBoot]
			},
			:ServerPool => {
				:has_multiples => true,
				:cfg_name => "server_pool",
				:cfg_plural => "server_pools",
				:interface => self.const_get("ServerPool"),
				:class => generic_class_methods,
				:instance => generic_instance_methods
			},
			:VPC => {
				:has_multiples => true,
				:cfg_name => "vpc",
				:cfg_plural => "vpcs",
				:interface => self.const_get("VPC"),
				:class => generic_class_methods + [:findSubnet, :listSubnets, :isSubnetPrivate?, :getDefaultRoute],
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
		# @param type [String]: The resource type. Can be the full class name, symbolic name, or Basket of Kittens configuration shorthand for the resource type.
		# @return [Class]: The cloud-specific class implementing this resource
		def self.artifact(cloud = MU::Config.defaultCloud, type)
			raise MuError, "cloud argument to MU::Cloud.artifact cannot be nil" if cloud.nil?
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

		@@resource_types.each_pair { |name, attrs|
			Object.const_get("MU").const_get("Cloud").const_get(name).class_eval {
				attr_reader :config
				attr_reader :cloud
				attr_reader :environment
				attr_reader :deploydata
				attr_reader :cloudclass
				attr_reader :cloudobj
				def self.shortname
					name.sub(/.*?::([^:]+)$/, '\1')
				end

				def initialize(mommacat: nil,
											 mu_name: nil,
											 kitten_cfg: kitten_cfg)
					raise MuError, "Cannot invoke Cloud objects without a configuration" if kitten_cfg.nil?
					@deploy = mommacat
					@config = kitten_cfg
					@cloud = kitten_cfg['cloud']
					@environment = kitten_cfg['environment']
					@deploydata = mommacat.deployment
					@cloudclass = MU::Cloud.artifact(@cloud, self.class.shortname)
# XXX require subclass to provide attr_readers of @config and @deploy
					if mu_name.nil?
						@cloudobj = @cloudclass.new(mommacat: mommacat, kitten_cfg: kitten_cfg)
					else
						@cloudobj = @cloudclass.new(mommacat: mommacat, kitten_cfg: kitten_cfg, mu_name: mu_name)
					end
				end

				# Retrieve all of the known metadata for this resource.
				# @param id [String]: The cloud platform's identifier for the resource we're describing.
				# @param node [String]: Identify a specific node to return. Types such as Server can have multiple instantiated resources of the same name, and this parameter allows us to request the description of a specific instance.
				# @return [Array<Hash>]
				def describe(id = nil, node = nil)
					res_type = self.class.cfg_name
					res_name = @config['name']
					deploydata = MU::MommaCat.getResourceDeployStruct(res_type, name: res_name, deploy_id: @deploy.mu_id, use_cache: false)
					cloud_desc, junk = self.class.find(name: res_name, deploy_id: @deploy.mu_id, region: @config['region'], id: id)
					# We asked for a specific node, return it if available
					if !node.nil? and deploydata.is_a?(Hash) and deploydata.has_key?(node)
						deploydata = deploydata[node]
					end

					return [@config['mu_name'], @config, deploydata, cloud_desc]
				end

				def self.cfg_plural
					MU::Cloud.resource_types[shortname.to_sym][:cfg_plural]
				end
				def self.cfg_name
					MU::Cloud.resource_types[shortname.to_sym][:cfg_name]
				end

				def self.find(*flags)
					MU::Cloud.supportedClouds.each { |cloud|
						begin
							cloudclass = MU::Cloud.artifact(cloud, shortname)
							found = cloudclass.find(flags.first)
							return found if !found.nil? # XXX actually, we should merge all results
						rescue MuCloudResourceNotImplemented
						end
					}
				end

# This method should only exist for MU::Cloud::DNSZone
				def self.genericMuDNSEntry(*flags)
# XXX have this be a global config for where Mu puts its stuff
					cloudclass = MU::Cloud.artifact(MU::Config.defaultCloud, "DNSZone")
					cloudclass.genericMuDNSEntry(flags.first)
				end

				def self.cleanup(*flags)
					MU::Cloud.supportedClouds.each { |cloud|
						begin
							cloudclass = MU::Cloud.artifact(cloud, shortname)
							MU.log "Invoking #{cloudclass}.cleanup", MU::DEBUG, details: flags
							cloudclass.cleanup(flags.first)
						rescue MuCloudResourceNotImplemented
						end
					}
				end

				# Wrap the instance methods that this cloud resource type has to
				# implement.
				MU::Cloud.resource_types[name.to_sym][:instance].each { |method|
					define_method method do
						MU.log "Invoking #{@cloudobj}.#{method}", MU::NOTICE
						@cloudobj.method(method).call
						if method == :create or method == :groom or method == :postBoot
							@cloudobj.method(:notify).call
						end
					end
				} # end instance method list
			} # end dynamic class generation block
		} # end resource type iteration

	end

end
