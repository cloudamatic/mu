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

	# A firewall ruleset as configured in {MU::Config::BasketofKittens::firewall_rules}
	class FirewallRule

		# The {MU::Config::BasketofKittens} name for a single resource of this class.
		def self.cfg_name; "firewall_rule".freeze end
		# The {MU::Config::BasketofKittens} name for a collection of resources of this class.
		def self.cfg_plural; "firewall_rules".freeze end
		# Whether {MU::Deploy} should hold creation of other resources which depend on this resource until the latter has been created.
		def self.deps_wait_on_my_creation; true.freeze end
		# Whether {MU::Deploy} should hold creation of this resource until resources on which it depends have been fully created and deployed.
		def self.waits_on_parent_completion; false.freeze end

		@deploy = nil
		@ruleset = nil
		@admin_sgs = Hash.new
		@admin_sg_semaphore = Mutex.new

		# @param deployer [MU::Deploy]: A {MU::Deploy} object, typically associated with an in-progress deployment.
		# @param ruleset [Hash]: The full {MU::Config} resource declaration as defined in {MU::Config::BasketofKittens::firewall_rules}
		def initialize(deployer, ruleset)
			@deploy = deployer
			@ruleset = ruleset
			MU.setVar("curRegion", @ruleset['region']) if !@ruleset['region'].nil?
		end

		# Called by {MU::Deploy#createResources}
		def create
			# old-style VPC reference
			if !@ruleset['vpc_id'].nil? or !@ruleset['vpc_name'].nil?
				existing_vpc, vpc_name = MU::VPC.find(
					id: @ruleset['vpc_id'],
					name: @ruleset['vpc_name'],
					region: @ruleset['region']
				)
				if existing_vpc.nil?
					MU.log "Couldn't find VPC matching id #{@ruleset['vpc_id']}", MU::ERR if @ruleset['vpc_id']
					MU.log "Couldn't find VPC matching name #{@ruleset['vpc_name']}", MU::ERR if @ruleset['vpc_name']
					raise "Couldn't find VPC matching id #{@ruleset['vpc_id']}" if @ruleset['vpc_id']
					raise "Couldn't find VPC matching name #{@ruleset['vpc_name']}" if @ruleset['vpc_name']
				end
				vpc_id = existing_vpc.vpc_id
			# new-style VPC reference
			elsif !@ruleset['vpc'].nil?
				vpc_id, subnet_ids, nat_host_name, nat_ssh_user = MU::VPC.parseVPC(@ruleset['vpc'])
			end
			@ruleset['sg_id'] = MU::FirewallRule.createEc2SG(
					@ruleset['name'],
					[],
					vpc_id: vpc_id,
					region: @ruleset['region']
			)
		end

		# Called by {MU::Deploy#createResources}
		def deploy
			MU::FirewallRule.setRules(
					@ruleset['sg_id'],
					@ruleset['rules'],
					add_to_self: @ruleset['self-referencing'],
					region: @ruleset['region']
				)
		end

		# Log metadata about this ruleset to the currently running deployment's
		# metadata.
		# @param name [String]: The MU resource name of the ruleset.
		# @param sg_id [String]: The cloud provider identifier of the ruleset.
		def self.notifyDeploy(name, sg_id, region: MU.curRegion)
			sg_data = MU.structToHash(
					MU::FirewallRule.find(sg_id: sg_id, region: region)
				)
			sg_data["group_id"] = sg_id
			MU::Deploy.notify("firewall_rules", name, sg_data)
		end

		# Insert a rule into an existing security group.
		#
		# @param sg_id [String]: The cloud provider's identifier for the group to modify.
		# @param hosts [Array<String>]: An array of CIDR network addresses to which this rule will apply.
		# @param proto [String]: One of "tcp," "udp," or "icmp"
		# @param port [Integer]: A port number. Only valid with udp or tcp.
		# @param egress [Boolean]: Whether this is an egress ruleset, instead of ingress.
		# @param sg_name [String]: A human-readable name for this resource.
		# @param port_range [String]: A port range descriptor (e.g. 0-65535). Only valid with udp or tcp.
		# @param region [String]: The cloud provider region
		# @return [void]
		def self.addRule(sg_id, hosts,
																				proto: proto = "tcp",
																				port: port = nil,
																				egress: egress = false,
																				sg_name: sg_name = "",
																				port_range: port_range = "0-65535",
																				region: MU.curRegion
																			)
			rule = Hash.new
			rule["proto"] = proto
			if hosts.is_a?(String)
				rule["hosts"] = [hosts]
			else
				rule["hosts"] = hosts
			end
			if port != nil
				port = port.to_s if !port.is_a?(String)
				rule["port"] = port
			else
				rule["port_range"] = port_range
			end
			ec2_rule = MU::FirewallRule.convertToEc2([rule], region: region)

			begin
				if egress
					MU.ec2(region).authorize_security_group_egress(
						group_id: sg_id,
						ip_permissions: ec2_rule
					)
				else
					MU.ec2(region).authorize_security_group_ingress(
						group_id: sg_id,
						ip_permissions: ec2_rule
					)
				end
			rescue Aws::EC2::Errors::InvalidPermissionDuplicate => e
				MU.log "Attempt to add duplicate rule to #{sg_id}", MU::DEBUG, details: ec2_rule
			end
		end
		
		# Manufacture an EC2 security group.
		#
		# @param name [String]: A human-readable resource name.
		# @param rules [Hash]: Firewall rules as defined and validated by MU::Config
		# @param description [String]: A long-form human-readable description.
		# @param vpc_id [String]: The cloud provider's identifier for a Virtual Private Cloud 
		# @param add_to_self [Boolean]: Add this ruleset to itself, so that all resources associated with this ruleset will also be considered "allowed hosts."
		# @param region [String]: The cloud provider region
		# @return [String]: The cloud provider's identifier for this resource.
		def self.createEc2SG(name, rules, description: description, vpc_id: vpc_id, add_to_self: add_to_self = false, region: MU.curRegion)
			groupname = MU::MommaCat.getResourceName(name)
			description = groupname if description.nil?

			MU.log "Creating EC2 Security Group #{groupname}"

			sg_struct = {
				:group_name => groupname,
				:description => description
			}
			if !vpc_id.nil?
				sg_struct[:vpc_id] = vpc_id
				groupname = MU::MommaCat.getResourceName(name, need_unique_string: true)
				sg_struct[:group_name] = groupname
			end

			begin
				secgroup = MU.ec2(region).create_security_group(sg_struct)
			rescue Aws::EC2::Errors::InvalidGroupDuplicate
				MU.log "EC2 Security Group #{groupname} already exists, using it", MU::WARN
				secgroup = MU::FirewallRule.find(name: groupname, region: region)
			end

			begin
				MU.ec2(region).describe_security_groups(group_ids: [secgroup.group_id])
			rescue Aws::EC2::Errors::InvalidGroupNotFound => e
				MU.log "#{secgroup.group_id} not yet ready, waiting...", MU::NOTICE
				sleep 10
				retry
			end

			MU::MommaCat.createStandardTags secgroup.group_id, region: region
			MU::MommaCat.createTag secgroup.group_id, "Name", groupname, region: region

			if !rules.nil? and rules.size > 0
				egress = false
				egress = true if !vpc_id.nil?
				# XXX the egress logic here is a crude hack, this really needs to be
				# done at config level
				MU::FirewallRule.setRules(
						secgroup.group_id,
						rules,
						add_to_self: add_to_self,
						ingress: true,
						egress: egress,
						region: region
				)
			end

			MU.log "EC2 Security Group #{groupname} is #{secgroup.group_id}", MU::DEBUG
			MU::FirewallRule.notifyDeploy(name, secgroup.group_id, region: region)
			return secgroup.group_id
		end

		# Allow our MU server into our new child instances. Security Groups are
		# VPC specific (and Classic is its own thing), so maintain one for each.
		# @param vpc_id [String]: The cloud provider identifier for the VPC for this security group, if applicable.
		# @param add_admin_ip [String]: Insert an additional host to allow, along with the MU master.
		# @param region [String]: The cloud provider region
		def self.setAdminSG(vpc_id: vpc_id, add_admin_ip: add_admin_ip, region: MU.curRegion)
			@admin_sg_semaphore.synchronize {
				if @admin_sgs['#CLASSIC'] and !vpc_id
					extant_sg = @admin_sgs['#CLASSIC']
				elsif @admin_sgs[vpc_id] and vpc_id
					extant_sg = @admin_sgs[vpc_id]
				end

				# If we're hiding behind a NAT or something, make sure our external
				# IP makes it into the admin SG.
				add_admin_ip = MU.mu_public_ip if add_admin_ip.nil?
	
				hosts = Array.new
				hosts << "#{add_admin_ip}/32" if add_admin_ip
				if vpc_id.nil?
					admin_sg_name = MU.mu_id + "-ADMIN"
				else
					admin_sg_name = MU.mu_id + "-ADMIN-" + vpc_id.upcase
				end
	
				if extant_sg != nil
					if add_admin_ip != nil
						MU.log "Modifying EC2 Security Group #{admin_sg_name} to add #{add_admin_ip}"
						ec2_rules = MU::FirewallRule.convertToEc2(MU::FirewallRule.stdAdminRules(hosts), region: region)

						MU::FirewallRule.addRule(extant_sg, hosts, proto: "tcp", port_range: "0-65535", region: region)
						MU::FirewallRule.addRule(extant_sg, hosts, proto: "udp", port_range: "0-65535", region: region)
						MU::FirewallRule.addRule(extant_sg, hosts, proto: "icmp", port_range: "-1", region: region)
					end
	
					return extant_sg
				end
	
				# Create this group from scratch if it wasn't already around
				hosts << "#{MU.my_private_ip}/32"
				hosts << "#{MU.my_public_ip}/32" if MU.my_public_ip != nil
				rules = MU::FirewallRule.stdAdminRules(hosts)
	
				sg = createEc2SG("ADMIN", rules, description: "Administrative security group for deploy #{MU.mu_id}. Lets our Mu Master in.", vpc_id: vpc_id, region: region)
				if vpc_id != nil
					@admin_sgs[vpc_id] = sg
				else
					@admin_sgs['#CLASSIC'] = sg
				end

				return sg
			}
		end

		# Locate an existing Firewall Rule and return the cloud provider's
		# complete description thereof.
		#
		# @param sg_id [String]: The cloud provider's identifier for this resource.
		# @param name [String]: This parameter will attempt first to find a MU resource with the given name string in the current deployment, and failing that will attempt to find a resource with a matching Name tag.
		# @param region [String]: The cloud provider region
		# @return [OpenStruct]: The cloud provider's full description of this resource.
		def self.find(sg_id: sg_id = nil, name: name = nil, region: MU.curRegion)
			return nil if !sg_id and !name
			MU.log "find invoked with sg_id: #{sg_id}, name: #{name}, region: #{region}", MU::DEBUG, details: caller

			if sg_id.nil? and !name.nil? and !MU::Deploy.deployment.nil? and !MU::Deploy.deployment['firewall_rules'].nil?

				if MU::Deploy.deployment['firewall_rules'][name] != nil
					sg_id = MU::Deploy.deployment['firewall_rules'][name]['group_id']
				end
			end

			if sg_id != nil
				retries = 0
				begin
					resp = MU.ec2(region).describe_security_groups(group_ids: [sg_id])
					return resp.data.security_groups.first
				rescue Aws::EC2::Errors::InvalidGroupNotFound => e
					if retries < 2
						MU.log "#{e.inspect} (#{name} in #{region}), retrying...", MU::WARN, details: caller
						retries = retries + 1
						sleep 5
						retry
					end

				end
			end

			if name
				resp = MU.ec2(region).describe_security_groups(
					filters:[
						{ name: "tag:Name", values: [name] }
					]
				)
				return resp.data.security_groups.first if resp
			end

		end


		private

		#########################################################################
		# Manufacture an EC2 security group. The second parameter, rules, is an
		# "ingress_rules" structure parsed and validated by MU::Config.
		#########################################################################
		def self.setRules(sg_id, rules, add_to_self: add_to_self = false, ingress: ingress = true, egress: egress = false, region: MU.curRegion)
			return if rules.nil? or rules.size == 0

			sg = MU::FirewallRule.find(sg_id: sg_id, region: region)
			raise "Couldn't find firewall ruleset with id #{sg_id}" if sg.nil?
			MU.log "Setting rules in Security Group #{sg.group_name} (#{sg_id})"

			# add_to_self means that this security is a "member" of its own rules
			# (which is to say, objects that have this SG are allowed in my these
			# rules)
			if add_to_self
				rules.each { |rule|
					if rule['sgs'].nil? or !rule['sgs'].include?(secgroup.group_id)
						new_rule = rule.clone
						new_rule.delete('hosts')
						rule['sgs'] = Array.new if rule['sgs'].nil?
						rule['sgs'] << sg_id
					end
				}
			end

			ec2_rules = MU::FirewallRule.convertToEc2(rules, region: region)

			# Creating an empty security group is ok, so don't freak out if we get
			# a null rule list.
			retries = 0
			if rules != nil
				MU.log "Rules for EC2 Security Group #{sg.group_name} (#{sg_id}): #{ec2_rules}", MU::DEBUG
				begin
					if ingress
						MU.ec2(region).authorize_security_group_ingress(
							group_id: sg_id,
							ip_permissions: ec2_rules
						)
					end
					if egress
						MU.ec2(region).authorize_security_group_egress(
							group_id: sg_id,
							ip_permissions: ec2_rules
						)
					end
				rescue Aws::EC2::Errors::InvalidGroupNotFound => e
					MU.log "#{sg.group_name} does not yet exist", MU::WARN
					retries = retries + 1
					if retries < 10
						sleep 10
						retry
					else
						raise e
					end
				rescue Aws::EC2::Errors::InvalidPermissionDuplicate => e
					MU.log "Attempt to add duplicate rule to #{sg.group_name}", MU::DEBUG, details: ec2_rules
				end
			end

			MU::FirewallRule.notifyDeploy(sg.group_name, sg_id, region: region)
			return sg_id
		end

		#########################################################################
		# Convert our config languages description of firewall rules into Amazon's.
		# This rule structure is as defined in MU::Config.
		#########################################################################
		def self.convertToEc2(rules, region: MU.curRegion)
			ec2_rules = []
			if rules != nil
				rules.each { |rule|
					ec2_rule = Hash.new
					rule['proto'] = "tcp" if rule['proto'].nil? or rule['proto'].empty?
					ec2_rule[:ip_protocol] = rule['proto']

					p_start = nil
					p_end = nil
					if rule['port_range']
						p_start, p_end = rule['port_range'].split(/\s*-\s*/)
					elsif rule['port']
						p_start = rule['port']
						p_end = rule['port']
					elsif rule['proto'] != "icmp"
						MU.log "Can't create a TCP or UDP security group rule without specifying ports.", MU::ERR, details: rule
						raise "Can't create a TCP or UDP security group rule without specifying ports."
					end
					if rule['proto'] != "icmp"
						if p_start.nil? or p_end.nil?
							raise "Got nil ports out of rule #{rule}"
						end
						ec2_rule[:from_port] = p_start.to_i
						ec2_rule[:to_port] = p_end.to_i
					else
						ec2_rule[:from_port] = -1
						ec2_rule[:to_port] = -1
					end

					if (!defined? rule['hosts'] or !rule['hosts'].is_a?(Array)) and
						 (!defined? rule['sgs'] or !rule['sgs'].is_a?(Array)) and
						 (!defined? rule['lbs'] or !rule['lbs'].is_a?(Array))
						raise "One of 'hosts', 'sgs', or 'lbs' in rules provided to createEc2SG must be an array."
					end

					if !rule['hosts'].nil?
						ec2_rule[:ip_ranges] = Array.new
						rule['hosts'].each { |cidr|
							ec2_rule[:ip_ranges] << { cidr_ip: cidr }
						}
					end
					
					if !rule['lbs'].nil?
						ec2_rule[:ip_ranges] = Array.new
						rule['lbs'].each { |lb_name|
							lb = MU::LoadBalancer.find(name: lb_name, dns_name: lb_name, region: region)
							if lb.nil?
								MU.log "Couldn't find a Load Balancer named #{lb_name}", MU::ERR
								raise "deploy failure"
							end
							ec2_rule[:user_id_group_pairs] = Array.new
# XXX nuh-uh, don't do this for every SG, just the default one
							lb.security_groups.each { |lb_sg|
								ec2_rule[:user_id_group_pairs] << {
									user_id: MU.account_number,
									group_id: lb_sg
								}
							}
						}
					end

					if !rule['sgs'].nil?
						ec2_rule[:user_id_group_pairs] = Array.new if ec2_rule[:user_id_group_pairs].nil?
						rule['sgs'].each { |sg_name|
							if sg_name.match(/^sg-/)
								sg = MU::FirewallRule.find(sg_id: sg_name, region: region)
							else
								sg = MU::FirewallRule.find(name: sg_name, region: region)
							end
							if sg.nil?
								raise "Attempted to reference non-existing Security Group #{sg_name}"
							end
							ec2_rule[:user_id_group_pairs] << {
								user_id: MU.account_number,
								group_id: sg.group_id
							}
						}
					end

					if !ec2_rule[:user_id_group_pairs].nil? and
							ec2_rule[:user_id_group_pairs].size > 0 and
							!ec2_rule[:ip_ranges].nil? and
							ec2_rule[:ip_ranges].size > 0
						MU.log "Cannot specify ip_ranges and user_id_group_pairs", MU::ERR
						raise "Cannot specify ip_ranges and user_id_group_pairs"
					end

					if !ec2_rule[:user_id_group_pairs].nil? and
							ec2_rule[:user_id_group_pairs].size > 0
						ec2_rule.delete(:ip_ranges)
					elsif !ec2_rule[:ip_ranges].nil? and
							ec2_rule[:ip_ranges].size > 0
						ec2_rule.delete(:user_id_group_pairs)
					end

					ec2_rules << ec2_rule
				}
			end
			return ec2_rules
		end

		# Generate a ruleset allowing blanket access. Mostly we use this to let
		# our child nodes get in touch with our MU/Chef server.
		# @param hosts [Array]: A list of CIDR addresses of hosts to allow.	
		# @return [Array<Hash>]: A set of rule structures derived from our hosts parameter.
		def self.stdAdminRules(hosts = [])
			if !hosts.is_a?(Array)
				raise "Got a non-array in stdAdminRules (should be list of CIDRs)"
			end
			hosts.uniq!

			rules = [
				{
					"proto" => "tcp",
					"port_range" => "0-65535",
					"hosts" => hosts
				},
				{
					"proto" => "udp",
					"port_range" => "0-65535",
					"hosts" => hosts
				},
				{
					"proto" => "icmp",
					"port_range" => "-1",
					"hosts" => hosts
				}
			]

			return rules
		end

	end #class
end #module
