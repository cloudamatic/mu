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
class Cloud
	class AWS
		# A server pool as configured in {MU::Config::BasketofKittens::server_pools}
		class ServerPool < MU::Cloud::ServerPool

			@deploy = nil
			@config = nil
			attr_reader :mu_name

			# @param mommacat [MU::MommaCat]: A {MU::Mommacat} object containing the deploy of which this resource is/will be a member.
			# @param kitten_cfg [Hash]: The fully parsed and resolved {MU::Config} resource descriptor as defined in {MU::Config::BasketofKittens::server_pools}
			def initialize(mommacat: mommacat, kitten_cfg: kitten_cfg, mu_name: mu_name)
				@deploy = mommacat
				@config = kitten_cfg
				if !mu_name.nil?
					@mu_name = mu_name
				end
				MU.setVar("curRegion", @config['region']) if !@config['region'].nil?
			end

			# Called automatically by {MU::Deploy#createResources}
			def create
				pool_name = MU::MommaCat.getResourceName(@config['name'])
				@mu_name = pool_name
				MU.setVar("curRegion", @config['region']) if !@config['region'].nil?

				asg_options = {
					:auto_scaling_group_name => pool_name,
					:default_cooldown => @config["default_cooldown"],
					:health_check_type => @config["health_check_type"],
					:health_check_grace_period => @config["health_check_grace_period"],
					:tags => []
				}

				MU::MommaCat.listStandardTags.each_pair { |name, value|
					asg_options[:tags] << { key: name, value: value, propagate_at_launch: true }
				}

				if @config['tags']
					@config['tags'].each { |tag|
						asg_options[:tags] << { key: tag['key'], value: tag['value'], propagate_at_launch: true }
					}
				end

				if @config["wait_for_nodes"] > 0
					MU.log "Setting pool #{pool_name} min_size and max_size to #{@config["wait_for_nodes"]} until bootstrapped"
					asg_options[:min_size] = @config["wait_for_nodes"]
					asg_options[:max_size] = @config["wait_for_nodes"]
				else
					asg_options[:min_size] = @config["min_size"]
					asg_options[:max_size] = @config["max_size"]
				end


				if @config["loadbalancers"]
					lbs = Array.new
# XXX refactor this into the LoadBalancer resource
					@config["loadbalancers"].each { |lb|
						if lb["existing_load_balancer"]
							lbs << lb["existing_load_balancer"]
							@deploy.deployment["loadbalancers"] = Array.new if !@deploy.deployment["loadbalancers"]
							@deploy.deployment["loadbalancers"] << {
								"name" => lb["existing_load_balancer"],
								"awsname" => lb["existing_load_balancer"]
# XXX probably have to query API to get the DNS name of this one
							}
						elsif lb["concurrent_load_balancer"]
							raise MuError, "No loadbalancers exist! I need one named #{lb['concurrent_load_balancer']}" if !@deploy.deployment["loadbalancers"]
							found = false
							@deploy.deployment["loadbalancers"].each_pair { |lb_name, deployed_lb|

								if lb_name == lb['concurrent_load_balancer']
									lbs << deployed_lb["awsname"]
									found = true
								end
							}
							raise MuError, "I need a loadbalancer named #{lb['concurrent_load_balancer']}, but none seems to have been created!" if !found
						end
					}
					asg_options[:load_balancer_names] = lbs
				end
				asg_options[:termination_policies] = @config["termination_policies"] if @config["termination_policies"]
				asg_options[:desired_capacity] = @config["desired_capacity"] if @config["desired_capacity"]

				basis = @config["basis"]

				if basis["launch_config"]
					nodes_name = MU::MommaCat.getResourceName(basis["launch_config"]["name"])
					launch_desc = basis["launch_config"]
					# XXX need to handle platform["windows"] in here

					if !launch_desc["server"].nil?
						if @deploy.deployment["images"].nil? or @deploy.deployment["images"][launch_desc["server"]].nil?
							raise MuError, "#{pool_name} needs an AMI from server #{launch_desc["server"]}, but I don't see one anywhere"
						end
						launch_desc["ami_id"] = @deploy.deployment["images"][launch_desc["server"]]["image_id"]
					elsif !launch_desc["instance_id"].nil?
						launch_desc["ami_id"] = MU::Cloud::AWS::Server.createImage(
																					name: pool_name,
																					instance_id: launch_desc["instance_id"]
																		)
					end
					MU::Cloud::AWS::Server.waitForAMI(launch_desc["ami_id"])

					launch_options = {
						:launch_configuration_name => pool_name,
						:image_id => launch_desc["ami_id"],
						:instance_type => launch_desc["size"],
						:key_name => @deploy.ssh_key_name,
						:ebs_optimized => launch_desc["ebs_optimized"],
						:instance_monitoring => { :enabled => launch_desc["monitoring"] },
					}
					if launch_desc["storage"]
						storage = Array.new
						launch_desc["storage"].each { |vol|
							storage << MU::Cloud::AWS::Server.convertBlockDeviceMapping(vol)
						}
						launch_options[:block_device_mappings ] = storage
						launch_options[:block_device_mappings].concat(MU::Cloud::AWS::Server.ephemeral_mappings)
					end
					launch_options[:spot_price ] = launch_desc["spot_price"] if launch_desc["spot_price"]
					launch_options[:kernel_id ] = launch_desc["kernel_id"] if launch_desc["kernel_id"]
					launch_options[:ramdisk_id ] = launch_desc["ramdisk_id"] if launch_desc["ramdisk_id"]
					launch_options[:iam_instance_profile] = MU::Cloud::AWS::Server.createIAMProfile("ServerPool-"+@config['name'], base_profile: launch_desc['iam_role'], extra_policies: launch_desc['iam_policies'])
					@config['iam_role'] = launch_options[:iam_instance_profile]

				if !@config["vpc_zone_identifier"].nil? or !@config["vpc"].nil?
					launch_options[:associate_public_ip_address] = @config["associate_public_ip"]
				end

					instance_secret = Password.random(50)
					MU.mommacat.saveSecret("default", instance_secret, "instance_secret")

					launch_options[:user_data ] = Base64.encode64(
						MU::Cloud::AWS::Server.fetchUserdata(
							platform: @config["platform"],
							template_variables: {
								"deployKey" => Base64.urlsafe_encode64(MU.mommacat.public_key),
								"deploySSHKey" => @deploy.ssh_public_key,
								"muID" => MU.deploy_id,
								"muUser" => MU.chef_user,
								"publicIP" => MU.mu_public_ip,
								"skipApplyUpdates" => @config['skipinitialupdates'],
								"windowsAdminName" => @config['windows_admin_username'],
								"resourceName" => @config["name"],
								"resourceType" => "server_pool"
							},
							custom_append: @config['userdata_script']
						)
					)

					launch_options[:user_data ] = launch_desc["user_data"] if launch_desc["user_data"]

				elsif basis["server"]
					nodes_name = MU::MommaCat.getResourceName(basis["server"])
					srv_name = basis["server"]

					if @deploy.deployment['servers'] != nil and
							@deploy.deployment['servers'][srv_name] != nil
						asg_options[:instance_id] = @deploy.deployment['servers'][srv_name]["instance_id"]
					end
				elsif basis["instance_id"]
					# TODO should go fetch the name tag or something
					nodes_name = MU::MommaCat.getResourceName(basis["instance_id"].gsub(/-/, ""))
					asg_options[:instance_id] = basis["instance_id"]
				end


				sgs = Array.new
#XXX should be passing optional rules to createEc2SG here
				if @config["vpc_zone_identifier"]
					asg_options[:vpc_zone_identifier] = @config["vpc_zone_identifier"]
				elsif @config["vpc"]
					vpc_id, subnet_ids, nat_host_name, nat_ssh_user = MU::Cloud::AWS::VPC.parseVPC(@config['vpc'])
					nat_instance, mu_name = MU::Cloud::Server.find(
						id: @config['vpc']['nat_host_id'],
						name: @config['vpc']['nat_host_name']
					)
					asg_options[:vpc_zone_identifier] = subnet_ids.join(",")

					if nat_instance != nil
						sgs << MU::Cloud::AWS::FirewallRule.setAdminSG(
							vpc_id: vpc_id,
							add_admin_ip: nat_instance["private_ip_address"]
						)
					else
						sgs << MU::Cloud::AWS::FirewallRule.setAdminSG(vpc_id: vpc_id)
					end
				end

				if asg_options[:vpc_zone_identifier] == nil
					sgs << MU::Cloud::AWS::FirewallRule.createEc2SG(@config['name'], nil, description: "AutoScale Group #{pool_name}")
					sgs << MU::Cloud::AWS::FirewallRule.setAdminSG
				end

				if !@config["add_firewall_rules"].nil?
					@config["add_firewall_rules"].each { |acl|
						sg = MU::Cloud::FirewallRule.find(sg_id: acl["rule_id"], name: acl["rule_name"])
						if sg.nil?
							MU.log "Couldn't find dependent security group #{acl} for server pool #{@config['name']}", MU::ERR, details: MU.mommacat.deployment['firewall_rules']
							raise MuError, "deploy failure"
						end
						sgs << sg.group_id
					}
				end

				if launch_options
					launch_options[:security_groups] = sgs
					MU.log "Creating AutoScale Launch Configuration #{pool_name}", details: launch_options 
					retries = 0
					begin
						launch_config = MU::Cloud::AWS.autoscale.create_launch_configuration(launch_options)
					rescue Aws::AutoScaling::Errors::ValidationError => e
						if retries < 10
							MU.log "Got #{e.inspect} creating Launch Configuration #{pool_name}, retrying in case of lagging resources", MU::WARN
							retries = retries + 1
							sleep 10
							retry
						else
							raise MuError, "Got #{e.inspect} creating Launch Configuration #{pool_name}"
						end
					end
					asg_options[:launch_configuration_name] = pool_name
				end

				# Do the dance of specifying individual zones if we haven't asked to
				# use particular VPC subnets.
				if @config['zones'] == nil and asg_options[:vpc_zone_identifier] == nil
					@config["zones"] = MU::Cloud::AWS.listAZs(@config['region'])
					MU.log "Using zones from #{@config['region']}", MU::DEBUG, details: @config['zones']
				end
				asg_options[:availability_zones] = @config["zones"] if @config["zones"] != nil

				MU.log "Creating AutoScale group #{pool_name}", details: asg_options

				zones_to_try = @config["zones"]
				begin
					asg = MU::Cloud::AWS.autoscale.create_auto_scaling_group(asg_options)
				rescue Aws::AutoScaling::Errors::ValidationError => e
					if zones_to_try != nil and zones_to_try.size > 0
						MU.log "#{e.message}, retrying with individual AZs", MU::WARN
						asg_options[:availability_zones] = [zones_to_try.pop]
						retry
					else
						raise MuError, "#{e.message} creating AutoScale group #{pool_name}"
					end
				end

				if zones_to_try != nil and zones_to_try.size < @config["zones"].size
					zones_to_try.each { |zone|
						begin
							MU::Cloud::AWS.autoscaleg.update_auto_scaling_group(
								auto_scaling_group_name: pool_name,
								availability_zones: [zone]
							)
						rescue Aws::AutoScaling::Errors::ValidationError => e
							MU.log "Couldn't enable Availability Zone #{zone} for AutoScale Group #{pool_name} (#{e.message})", MU::WARN
						end
					}

				end

				if @config["scaling_policies"] and @config["scaling_policies"].size > 0
					@config["scaling_policies"].each { |policy|
						policy_params = {
							:auto_scaling_group_name => pool_name,
							:policy_name => MU::MommaCat.getResourceName("#{@config['name']}-#{policy['name']}"),
							:scaling_adjustment => policy['adjustment'],
							:adjustment_type => policy['type'],
							:cooldown => policy['cooldown']
						}
						if !policy['min_adjustment_step'].nil?
							policy_params[:min_adjustment_step] = policy['min_adjustment_step']
						end
						MU::Cloud::AWS.autoscale.put_scaling_policy(policy_params)
					}
				end

				# Wait and see if we successfully bring up some instances
				attempts = 0
				begin
					sleep 5
					desc = MU::Cloud::AWS.autoscale.describe_auto_scaling_groups(auto_scaling_group_names: [pool_name]).auto_scaling_groups.first
					MU.log "Looking for #{desc.min_size} instances in #{pool_name}, found #{desc.instances.size}", MU::DEBUG
					attempts = attempts + 1
					if attempts > 25 and desc.instances.size == 0
						MU.log "No instances spun up after #{5*attempts} seconds, something's wrong with Autoscale group #{pool_name}", MU::ERR, details: MU::Cloud::AWS.autoscale.describe_scaling_activities(auto_scaling_group_name: pool_name).activities
						raise MuError, "No instances spun up after #{5*attempts} seconds, something's wrong with Autoscale group #{pool_name}"
					end
				end while desc.instances.size < desc.min_size
				MU.log "#{desc.instances.size} instances spinning up in #{pool_name}"

				# If we're holding to bootstrap some nodes, do so, then set our min/max
				# sizes to their real values.
				if @config["wait_for_nodes"] > 0
					MU.log "Waiting for #{@config["wait_for_nodes"]} nodes to fully bootstrap before proceeding"
					parent_thread_id = Thread.current.object_id
					groomthreads = Array.new
					desc.instances.each { |member|
						begin
							instance = MU::Cloud::Server.find(id: member.instance_id)
							groomthreads << Thread.new {
								MU.dupGlobals(parent_thread_id)
								MU.mommacat.groomNode(instance, @config['name'], "server_pool", reraise_fail: true, sync_wait: @config['dns_sync_wait'])
							}
						rescue Exception => e
							if !instance.nil? and !done
								MU.log "Aborted before I could finish setting up #{@config['name']}, cleaning it up. Stack trace will print once cleanup is complete.", MU::WARN if !@deploy.nocleanup
								MU::MommaCat.unlockAll
								if !@deploy.nocleanup
									Thread.new {
										MU.dupGlobals(parent_thread_id)
										MU::Cloud::AWS::Server.terminateInstance(id: instance.instance_id)
									}
								end
							end
							raise MuError, e.inspect
						end
					}
					groomthreads.each { |t|
						t.join
					}
					MU.log "Setting min_size to #{@config['min_size']} and max_size to #{@config['max_size']}"
					MU::Cloud::AWS.autoscale.update_auto_scaling_group(
						auto_scaling_group_name: pool_name,
						min_size: @config['min_size'],
						max_size: @config['max_size']
					)
				end
				MU.log "See /var/log/mu-momma-cat.log for asynchronous bootstrap progress.", MU::NOTICE

				return asg
			end

			# This is a NOOP right now, because we're really an empty generator for
			# Servers, and that's what we care about having in deployment
			# descriptors. Should we log some stuff though?
			def notify
			end

			# placeholder
			def self.find
			end

			# Remove all autoscale groups associated with the currently loaded deployment.
			# @param noop [Boolean]: If true, will only print what would be done
			# @param ignoremaster [Boolean]: If true, will remove resources not flagged as originating from this Mu server
			# @param region [String]: The cloud provider region
			# @return [void]
			def self.cleanup(noop: false, ignoremaster: false, region: MU.curRegion, flags: {})
				filters = [ { name: "key", values: ["MU-ID"] } ]
				if !ignoremaster
					filters << { name: "key", values: ["MU-MASTER-IP"] }
				end
				resp = MU::Cloud::AWS.autoscale(region).describe_tags(
					filters: filters
				)
				return nil if resp.tags.nil? or resp.tags.size == 0

				maybe_purge = []
				no_purge = []

				resp.data.tags.each { |asg|
					if asg.resource_type != "auto-scaling-group"
						no_purge << asg.resource_id
					end
					if asg.key == "MU-MASTER-IP" and asg.value != MU.mu_public_ip and !ignoremaster
						no_purge << asg.resource_id
					end
					if (asg.key == "MU-ID" or asg.key == "CAP-ID") and asg.value == MU.deploy_id
						maybe_purge << asg.resource_id
					end
				}

				maybe_purge.each { |resource_id|
					next if no_purge.include?(resource_id)
					MU.log "Removing AutoScale group #{resource_id}"
					next if noop
					retries = 0
					begin 
						MU::Cloud::AWS.autoscale(region).delete_auto_scaling_group(
							auto_scaling_group_name: resource_id,
# XXX this should obey @force
							force_delete: true
						)
					rescue Aws::AutoScaling::Errors::InternalFailure => e
						if retries < 5
							MU.log "Got #{e.inspect} while removing AutoScale group #{resource_id}.", MU::WARN
							sleep 10
							retry
						else
							MU.log "Failed to delete AutoScale group #{resource_id}", MU::ERR
						end
					end

					# Generally there should be a launch_configuration of the same name
# XXX search for these independently, too?
					retries = 0
					begin
						MU.log "Removing AutoScale Launch Configuration #{resource_id}"
						MU::Cloud::AWS.autoscale(region).delete_launch_configuration(
							launch_configuration_name: resource_id
						)
					rescue Aws::AutoScaling::Errors::ValidationError => e
						MU.log "No such Launch Configuration #{resource_id}"
					rescue Aws::AutoScaling::Errors::InternalFailure => e
						if retries < 5
							MU.log "Got #{e.inspect} while removing Launch Configuration #{resource_id}.", MU::WARN
							sleep 10
							retry
						else
							MU.log "Failed to delete Launch Configuration #{resource_id}", MU::ERR
						end
					end
				}
				return nil
			end
		end
	end
	end
end
