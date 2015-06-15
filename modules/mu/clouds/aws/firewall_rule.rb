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

	class AWS
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

			# @param mommacat [MU::MommaCat]: A {MU::Mommacat} object containing the deploy of which this resource is/will be a member.
			# @param kitten_cfg [Hash]: The fully parsed and resolved {MU::Config} resource descriptor as defined in {MU::Config::BasketofKittens::firewall_rules}
			def initialize(mommacat: mommacat, kitten_cfg: kitten_cfg)
				@deploy = mommacat
				@ruleset = kitten_cfg
				MU.setVar("curRegion", @ruleset['region']) if !@ruleset['region'].nil?
			end

			# Called by {MU::Deploy#createResources}
			def create
				# old-style VPC reference
				if !@ruleset['vpc_id'].nil? or !@ruleset['vpc_name'].nil?
					existing_vpc, vpc_name = MU::AWS::VPC.find(
						id: @ruleset['vpc_id'],
						name: @ruleset['vpc_name'],
						region: @ruleset['region']
					)
					if existing_vpc.nil?
						MU.log "Couldn't find VPC matching id #{@ruleset['vpc_id']}", MU::ERR if @ruleset['vpc_id']
						MU.log "Couldn't find VPC matching name #{@ruleset['vpc_name']}", MU::ERR if @ruleset['vpc_name']
						raise MuError, "Couldn't find VPC matching id #{@ruleset['vpc_id']}" if @ruleset['vpc_id']
						raise MuError, "Couldn't find VPC matching name #{@ruleset['vpc_name']}" if @ruleset['vpc_name']
					end
					vpc_id = existing_vpc.vpc_id
				# new-style VPC reference
				elsif !@ruleset['vpc'].nil?
					vpc_id, subnet_ids, nat_host_name, nat_ssh_user = MU::AWS::VPC.parseVPC(@ruleset['vpc'])
				end
				@ruleset['sg_id'] = MU::AWS::FirewallRule.createEc2SG(
						@ruleset['name'],
						[],
						vpc_id: vpc_id,
						region: @ruleset['region']
				)
			end

			# Called by {MU::Deploy#createResources}
			def groom
				MU::AWS::FirewallRule.setRules(
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
						MU::AWS::FirewallRule.find(sg_id: sg_id, region: region)
					)
				sg_data["group_id"] = sg_id
				MU.mommacat.notify("firewall_rules", name, sg_data)
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
				ec2_rule = MU::AWS::FirewallRule.convertToEc2([rule], region: region)

				begin
					if egress
						MU::AWS.ec2(region).authorize_security_group_egress(
							group_id: sg_id,
							ip_permissions: ec2_rule
						)
					else
						MU::AWS.ec2(region).authorize_security_group_ingress(
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
					secgroup = MU::AWS.ec2(region).create_security_group(sg_struct)
				rescue Aws::EC2::Errors::InvalidGroupDuplicate
					MU.log "EC2 Security Group #{groupname} already exists, using it", MU::WARN
					secgroup = MU::AWS::FirewallRule.find(name: groupname, region: region)
				end

				begin
					MU::AWS.ec2(region).describe_security_groups(group_ids: [secgroup.group_id])
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
					MU::AWS::FirewallRule.setRules(
							secgroup.group_id,
							rules,
							add_to_self: add_to_self,
							ingress: true,
							egress: egress,
							region: region
					)
				end

				MU.log "EC2 Security Group #{groupname} is #{secgroup.group_id}", MU::DEBUG
				MU::AWS::FirewallRule.notifyDeploy(name, secgroup.group_id, region: region)
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
							ec2_rules = MU::AWS::FirewallRule.convertToEc2(MU::AWS::FirewallRule.stdAdminRules(hosts), region: region)

							MU::AWS::FirewallRule.addRule(extant_sg, hosts, proto: "tcp", port_range: "0-65535", region: region)
							MU::AWS::FirewallRule.addRule(extant_sg, hosts, proto: "udp", port_range: "0-65535", region: region)
							MU::AWS::FirewallRule.addRule(extant_sg, hosts, proto: "icmp", port_range: "-1", region: region)
						end
		
						return extant_sg
					end
		
					# Create this group from scratch if it wasn't already around
					hosts << "#{MU.my_private_ip}/32"
					hosts << "#{MU.my_public_ip}/32" if MU.my_public_ip != nil
					rules = MU::AWS::FirewallRule.stdAdminRules(hosts)
		
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

				if sg_id.nil? and !name.nil? and !MU.mommacat.deployment.nil? and !MU.mommacat.deployment['firewall_rules'].nil?

					if MU.mommacat.deployment['firewall_rules'][name] != nil
						sg_id = MU.mommacat.deployment['firewall_rules'][name]['group_id']
					end
				end

				if sg_id != nil
					retries = 0
					begin
						resp = MU::AWS.ec2(region).describe_security_groups(group_ids: [sg_id])
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
					resp = MU::AWS.ec2(region).describe_security_groups(
						filters:[
							{ name: "tag:Name", values: [name] }
						]
					)

					return resp.data.security_groups.first if resp
				end

			end

			# Remove all security groups (firewall rulesets) associated with the currently loaded deployment.
			# @param noop [Boolean]: If true, will only print what would be done
			# @param ignoremaster [Boolean]: If true, will remove resources not flagged as originating from this Mu server
			# @param region [String]: The cloud provider region
			# @return [void]
			def self.cleanup(noop = false, ignoremaster = false, region: MU.curRegion)
				tagfilters = [
					{ name: "tag:MU-ID", values: [MU.mu_id] }
				]
				if !ignoremaster
					tagfilters << { name: "tag:MU-MASTER-IP", values: [MU.mu_public_ip] }
				end

				resp = MU::AWS.ec2(region).describe_security_groups(
					filters: tagfilters
				)

				resp.data.security_groups.each { |sg|
					MU.log "Revoking rules in EC2 Security Group #{sg.group_name} (#{sg.group_id})"

					if !noop
						ingress_to_revoke = Array.new
						egress_to_revoke = Array.new
						sg.ip_permissions.each { |hole|

							hole_hash = MU.structToHash(hole)
							if !hole_hash[:user_id_group_pairs].nil?
								hole[:user_id_group_pairs].each { |group_ref|
									group_ref.delete(:group_name) if group_ref.is_a?(Hash)
								}
							end
							ingress_to_revoke << MU.structToHash(hole)
							ingress_to_revoke.each { |rule|
								if !rule[:user_id_group_pairs].nil? and rule[:user_id_group_pairs].size == 0
									rule.delete(:user_id_group_pairs)
								end
								if !rule[:ip_ranges].nil? and rule[:ip_ranges].size == 0
									rule.delete(:ip_ranges)
								end
								if !rule[:prefix_list_ids].nil? and rule[:prefix_list_ids].size == 0
									rule.delete(:prefix_list_ids)
								end
							}
						}
						sg.ip_permissions_egress.each { |hole|
							hole_hash = MU.structToHash(hole)
							if !hole_hash[:user_id_group_pairs].nil? and hole_hash[:user_id_group_pairs].is_a?(Hash)
								hole[:user_id_group_pairs].each { |group_ref|
									group_ref.delete(:group_name)
								}
							end
							egress_to_revoke << MU.structToHash(hole)
							egress_to_revoke.each { |rule|
								if !rule[:user_id_group_pairs].nil? and rule[:user_id_group_pairs].size == 0
									rule.delete(:user_id_group_pairs)
								end
								if !rule[:ip_ranges].nil? and rule[:ip_ranges].size == 0
									rule.delete(:ip_ranges)
								end
								if !rule[:prefix_list_ids].nil? and rule[:prefix_list_ids].size == 0
									rule.delete(:prefix_list_ids)
								end
							}
						}
						begin
							if ingress_to_revoke.size > 0
								MU::AWS.ec2(region).revoke_security_group_ingress(
									group_id: sg.group_id,
									ip_permissions: ingress_to_revoke
								)
							end
							if egress_to_revoke.size > 0
								MU::AWS.ec2(region).revoke_security_group_egress(
									group_id: sg.group_id,
									ip_permissions: egress_to_revoke
								)
							end
						rescue Aws::EC2::Errors::InvalidPermissionNotFound
							MU.log "Rule in #{sg.group_id} disappeared before I could remove it", MU::WARN
						end
					end
				}

				resp.data.security_groups.each { |sg|
					MU.log "Removing EC2 Security Group #{sg.group_name}"

					retries = 0
					begin
					  MU::AWS.ec2(region).delete_security_group(group_id: sg.group_id) if !noop
					rescue Aws::EC2::Errors::InvalidGroupNotFound
						MU.log "EC2 Security Group #{sg.group_name} disappeared before I could delete it!", MU::WARN
					rescue Aws::EC2::Errors::DependencyViolation, Aws::EC2::Errors::InvalidGroupInUse
						if retries < 10
							MU.log "EC2 Security Group #{sg.group_name} is still in use, waiting...", MU::NOTICE
							sleep 10
							retries = retries + 1
							retry
						else
							MU.log "Failed to delete #{sg.group_name}", MU::ERR
						end
					end
				}
			end

			private

			#########################################################################
			# Manufacture an EC2 security group. The second parameter, rules, is an
			# "ingress_rules" structure parsed and validated by MU::Config.
			#########################################################################
			def self.setRules(sg_id, rules, add_to_self: add_to_self = false, ingress: ingress = true, egress: egress = false, region: MU.curRegion)
				return if rules.nil? or rules.size == 0

				sg = MU::AWS::FirewallRule.find(sg_id: sg_id, region: region)
				raise MuError, "Couldn't find firewall ruleset with id #{sg_id}" if sg.nil?
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

				ec2_rules = MU::AWS::FirewallRule.convertToEc2(rules, region: region)

				# Creating an empty security group is ok, so don't freak out if we get
				# a null rule list.
				retries = 0
				if rules != nil
					MU.log "Rules for EC2 Security Group #{sg.group_name} (#{sg_id}): #{ec2_rules}", MU::DEBUG
					begin
						if ingress
							MU::AWS.ec2(region).authorize_security_group_ingress(
								group_id: sg_id,
								ip_permissions: ec2_rules
							)
						end
						if egress
							MU::AWS.ec2(region).authorize_security_group_egress(
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
							raise MuError, "#{sg.group_name} does not exist"
						end
					rescue Aws::EC2::Errors::InvalidPermissionDuplicate => e
						MU.log "Attempt to add duplicate rule to #{sg.group_name}", MU::DEBUG, details: ec2_rules
					end
				end

				MU::AWS::FirewallRule.notifyDeploy(sg.group_name, sg_id, region: region)
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
							raise MuError, "Can't create a TCP or UDP security group rule without specifying ports."
						end
						if rule['proto'] != "icmp"
							if p_start.nil? or p_end.nil?
								raise MuError, "Got nil ports out of rule #{rule}"
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
							raise MuError, "One of 'hosts', 'sgs', or 'lbs' in rules provided to createEc2SG must be an array."
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
								lb = MU::AWS::LoadBalancer.find(name: lb_name, dns_name: lb_name, region: region)
								if lb.nil?
									MU.log "Couldn't find a Load Balancer named #{lb_name}", MU::ERR
									raise MuError, "deploy failure"
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
									sg = MU::AWS::FirewallRule.find(sg_id: sg_name, region: region)
								else
									sg = MU::AWS::FirewallRule.find(name: sg_name, region: region)
								end
								if sg.nil?
									raise MuError, "Attempted to reference non-existing Security Group #{sg_name}"
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
							raise MuError, "Cannot specify ip_ranges and user_id_group_pairs"
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
					raise MuError, "Got a non-array in stdAdminRules (should be list of CIDRs)"
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
	end #class
end #module
