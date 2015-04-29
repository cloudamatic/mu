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

	# A server pool as configured in {MU::Config::BasketofKittens::server_pools}
	class ServerPool
		# The {MU::Config::BasketofKittens} name for a single resource of this class.
		def self.cfg_name; "server_pool".freeze end
		# The {MU::Config::BasketofKittens} name for a collection of resources of this class.
		def self.cfg_plural; "server_pools".freeze end
		# Whether {MU::Deploy} should hold creation of other resources which depend on this resource until the latter has been created.
		def self.deps_wait_on_my_creation; false.freeze end
		# Whether {MU::Deploy} should hold creation of this resource until resources on which it depends have been fully created and deployed.
		def self.waits_on_parent_completion; true.freeze end

		@deploy = nil
		@pool = nil

		# @param deployer [MU::Deploy]: A {MU::Deploy} object, typically associated with an in-progress deployment.
		# @param asg [Hash]: The full {MU::Config} resource declaration as defined in {MU::Config::BasketofKittens::server_pools}
		def initialize(deployer, asg)
			@deploy = deployer
			@pool = asg
			MU.setVar("curRegion", @pool['region']) if !@pool['region'].nil?
		end

		# Called automatically by {MU::Deploy#createResources}
		def create
			keypairname, ssh_private_key, ssh_public_key = @deploy.createEc2SSHKey

			pool_name = MU::MommaCat.getResourceName(@pool['name'])
			MU.setVar("curRegion", @pool['region']) if !@pool['region'].nil?


			if @pool['platform'] == "windows"
				if !@deploy.winpass.nil?
					winpass = @deploy.winpass
				elsif !@pool['never-generate_admin_password']
					winpass = MU::Server.generateWindowsAdminPassword
				end
				if !winpass.nil?
					MU.mommacat.saveSecret("default", winpass, "windows_password")
				end
			end

			asg_options = {
				:auto_scaling_group_name => pool_name,
				:default_cooldown => @pool["default_cooldown"],
				:health_check_type => @pool["health_check_type"],
				:health_check_grace_period => @pool["health_check_grace_period"],
				:tags => []
			}

			MU::MommaCat.listStandardTags.each_pair { |name, value|
				asg_options[:tags] << { key: name, value: value, propagate_at_launch: true }
			}

			if @pool['tags']
				@pool['tags'].each { |tag|
					asg_options[:tags] << { key: tag['key'], value: tag['value'], propagate_at_launch: true }
				}
			end

			if @pool["wait_for_nodes"] > 0
				MU.log "Setting pool #{pool_name} min_size and max_size to #{@pool["wait_for_nodes"]} until bootstrapped"
				asg_options[:min_size] = @pool["wait_for_nodes"]
				asg_options[:max_size] = @pool["wait_for_nodes"]
			else
				asg_options[:min_size] = @pool["min_size"]
				asg_options[:max_size] = @pool["max_size"]
			end


			if @pool["loadbalancers"]
				lbs = Array.new
# XXX refactor this into the LoadBalancer resource
				@pool["loadbalancers"].each { |lb|
					if lb["existing_load_balancer"]
						lbs << lb["existing_load_balancer"]
						@deploy.deployment["loadbalancers"] = Array.new if !@deploy.deployment["loadbalancers"]
						@deploy.deployment["loadbalancers"] << {
							"name" => lb["existing_load_balancer"],
							"awsname" => lb["existing_load_balancer"]
# XXX probably have to query API to get the DNS name of this one
						}
					elsif lb["concurrent_load_balancer"]
						raise "No loadbalancers exist! I need one named #{lb['concurrent_load_balancer']}" if !@deploy.deployment["loadbalancers"]
						found = false
						@deploy.deployment["loadbalancers"].each_pair { |lb_name, deployed_lb|

							if lb_name == lb['concurrent_load_balancer']
								lbs << deployed_lb["awsname"]
								found = true
							end
						}
						raise "I need a loadbalancer named #{lb['concurrent_load_balancer']}, but none seems to have been created!" if !found
					end
				}
				asg_options[:load_balancer_names] = lbs
			end
			asg_options[:termination_policies] = @pool["termination_policies"] if @pool["termination_policies"]
			asg_options[:desired_capacity] = @pool["desired_capacity"] if @pool["desired_capacity"]

			basis = @pool["basis"]

			if basis["launch_config"]
				nodes_name = MU::MommaCat.getResourceName(basis["launch_config"]["name"])
				launch_desc = basis["launch_config"]
				# XXX need to handle platform["windows"] in here

				if !launch_desc["server"].nil?
					if @deploy.deployment["images"].nil? or @deploy.deployment["images"][launch_desc["server"]].nil?
						raise "#{pool_name} needs an AMI from server #{launch_desc["server"]}, but I don't see one anywhere"
					end
					launch_desc["ami_id"] = @deploy.deployment["images"][launch_desc["server"]]["image_id"]
				elsif !launch_desc["instance_id"].nil?
					launch_desc["ami_id"] = MU::Server.createImage(
																				name: pool_name,
																				instance_id: launch_desc["instance_id"]
																	)
				end
				MU::Server.waitForAMI(launch_desc["ami_id"])

				launch_options = {
					:launch_configuration_name => pool_name,
					:image_id => launch_desc["ami_id"],
					:instance_type => launch_desc["size"],
					:key_name => @deploy.keypairname,
					:ebs_optimized => launch_desc["ebs_optimized"],
					:instance_monitoring => { :enabled => launch_desc["monitoring"] },
				}
				if launch_desc["storage"]
					storage = Array.new
					launch_desc["storage"].each { |vol|
						storage << MU::Server.convertBlockDeviceMapping(vol)
					}
					launch_options[:block_device_mappings ] = storage
					launch_options[:block_device_mappings].concat(MU::Server.ephemeral_mappings)
				end
				launch_options[:spot_price ] = launch_desc["spot_price"] if launch_desc["spot_price"]
				launch_options[:kernel_id ] = launch_desc["kernel_id"] if launch_desc["kernel_id"]
				launch_options[:ramdisk_id ] = launch_desc["ramdisk_id"] if launch_desc["ramdisk_id"]
				launch_options[:iam_instance_profile] = MU::Server.createIAMProfile("ServerPool-"+@pool['name'], base_profile: launch_desc['iam_role'], extra_policies: launch_desc['iam_policies'])
				@pool['iam_role'] = launch_options[:iam_instance_profile]

			if !@pool["vpc_zone_identifier"].nil? or !@pool["vpc"].nil?
				launch_options[:associate_public_ip_address] = @pool["associate_public_ip"]
			end

				instance_secret = Password.random(50)
				MU.mommacat.saveSecret("default", instance_secret, "instance_secret")

				launch_options[:user_data ] = Base64.encode64(
					MU::Server.fetchUserdata(
						platform: @pool["platform"],
						template_variables: {
							"deployKey" => Base64.urlsafe_encode64(MU.mommacat.public_key),
							"deploySSHKey" => ssh_public_key,
							"muID" => MU.mu_id,
							"muUser" => MU.chef_user,
							"publicIP" => MU.mu_public_ip,
							"resourceName" => @pool["name"],
							"resourceType" => "server_pool"
						},
						custom_append: @pool['userdata_script']
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
			if @pool["vpc_zone_identifier"]
				asg_options[:vpc_zone_identifier] = @pool["vpc_zone_identifier"]
			elsif @pool["vpc"]
				vpc_id, subnet_ids, nat_host_name, nat_ssh_user = MU::VPC.parseVPC(@pool['vpc'])
				nat_instance, mu_name = MU::Server.find(
					id: @pool['vpc']['nat_host_id'],
					name: @pool['vpc']['nat_host_name']
				)
				asg_options[:vpc_zone_identifier] = subnet_ids.join(",")

				sgs << MU::FirewallRule.createEc2SG(@pool['name']+vpc_id.upcase, @pool['ingress_rules'], description: "AutoScale Group #{pool_name}", vpc_id: vpc_id)
				if nat_instance != nil
					sgs << MU::FirewallRule.setAdminSG(
						vpc_id: vpc_id,
						add_admin_ip: nat_instance["private_ip_address"]
					)
				else
					sgs << MU::FirewallRule.setAdminSG(vpc_id: vpc_id)
				end
			end

			if asg_options[:vpc_zone_identifier] == nil
				sgs << MU::FirewallRule.createEc2SG(@pool['name'], nil, description: "AutoScale Group #{pool_name}")
				sgs << MU::FirewallRule.setAdminSG
			end

			if !@pool["add_firewall_rules"].nil?
				@pool["add_firewall_rules"].each { |acl|
					sg = MU::FirewallRule.find(sg_id: acl["rule_id"], name: acl["rule_name"])
					if sg.nil?
						MU.log "Couldn't find dependent security group #{acl} for server pool #{@pool['name']}", MU::ERR, details: MU::Deploy.deployment['firewall_rules']
						raise "deploy failure"
					end
					sgs << sg.group_id
				}
			end

			if launch_options
				launch_options[:security_groups] = sgs
				MU.log "Creating AutoScale Launch Configuration #{pool_name}", details: launch_options 
				retries = 0
				begin
					launch_config = MU.autoscale.create_launch_configuration(launch_options)
				rescue Aws::AutoScaling::Errors::ValidationError => e
					if retries < 10
						MU.log "Got #{e.inspect} creating Launch Configuration #{pool_name}, retrying in case of lagging resources", MU::WARN
						retries = retries + 1
						sleep 10
						retry
					else
						raise e
					end
				end
				asg_options[:launch_configuration_name] = pool_name
			end

			# Do the dance of specifying individual zones if we haven't asked to
			# use particular VPC subnets.
			if @pool['zones'] == nil and asg_options[:vpc_zone_identifier] == nil
				@pool["zones"] = MU::Config.listAZs(@pool['region'])
				MU.log "Using zones from #{@pool['region']}", MU::DEBUG, details: @pool['zones']
			end
			asg_options[:availability_zones] = @pool["zones"] if @pool["zones"] != nil

			MU.log "Creating AutoScale group #{pool_name}", details: asg_options

			zones_to_try = @pool["zones"]
			begin
				asg = MU.autoscale.create_auto_scaling_group(asg_options)
			rescue Aws::AutoScaling::Errors::ValidationError => e
				if zones_to_try != nil and zones_to_try.size > 0
					MU.log "#{e.message}, retrying with individual AZs", MU::WARN
					asg_options[:availability_zones] = [zones_to_try.pop]
					retry
				else
					raise e
				end
			end

			if zones_to_try != nil and zones_to_try.size < @pool["zones"].size
				zones_to_try.each { |zone|
					begin
						MU.autoscaleg.update_auto_scaling_group(
							auto_scaling_group_name: pool_name,
							availability_zones: [zone]
						)
					rescue Aws::AutoScaling::Errors::ValidationError => e
						MU.log "Couldn't enable Availability Zone #{zone} for AutoScale Group #{pool_name} (#{e.message})", MU::WARN
					end
				}

			end

			if @pool["scaling_policies"] and @pool["scaling_policies"].size > 0
				@pool["scaling_policies"].each { |policy|
					policy_params = {
						:auto_scaling_group_name => pool_name,
						:policy_name => MU::MommaCat.getResourceName("#{@pool['name']}-#{policy['name']}"),
						:scaling_adjustment => policy['adjustment'],
						:adjustment_type => policy['type'],
						:cooldown => policy['cooldown']
					}
					if !policy['min_adjustment_step'].nil?
						policy_params[:min_adjustment_step] = policy['min_adjustment_step']
					end
					MU.autoscale.put_scaling_policy(policy_params)
				}
			end

			# Wait and see if we successfully bring up some instances
			attempts = 0
			begin
				sleep 5
				desc = MU.autoscale.describe_auto_scaling_groups(auto_scaling_group_names: [pool_name]).auto_scaling_groups.first
				MU.log "Looking for #{desc.min_size} instances in #{pool_name}, found #{desc.instances.size}", MU::DEBUG
				attempts = attempts + 1
				if attempts > 25 and desc.instances.size == 0
					MU.log "No instances spun up after #{5*attempts} seconds, something's wrong with Autoscale group #{pool_name}", MU::ERR, details: MU.autoscale.describe_scaling_activities(auto_scaling_group_name: pool_name).activities
					raise "No instances spun up after #{5*attempts} seconds, something's wrong with Autoscale group #{pool_name}"
				end
			end while desc.instances.size < desc.min_size
			MU.log "#{desc.instances.size} instances spinning up in #{pool_name}"

			# If we're holding to bootstrap some nodes, do so, then set our min/max
			# sizes to their real values.
			if @pool["wait_for_nodes"] > 0
				MU.log "Waiting for #{@pool["wait_for_nodes"]} nodes to fully bootstrap before proceeding"
				parent_thread_id = Thread.current.object_id
				groomthreads = Array.new
				desc.instances.each { |member|
					begin
						instance, mu_name = MU::Server.find(id: member.instance_id)
						groomthreads << Thread.new {
							MU.dupGlobals(parent_thread_id)
							MU.mommacat.groomNode(instance, @pool['name'], "server_pool", reraise_fail: true, sync_wait: @pool['dns_sync_wait'])
						}
					rescue Exception => e
						if !instance.nil? and !done
							MU.log "Aborted before I could finish setting up #{@pool['name']}, cleaning it up. Stack trace will print once cleanup is complete.", MU::WARN if !@deploy.nocleanup
							MU::MommaCat.unlockAll
							if !@deploy.nocleanup
								Thread.new {
									MU.dupGlobals(parent_thread_id)
									MU::Cleanup.terminate_instance(id: instance.instance_id)
								}
							end
						end
						raise e
					end
				}
				groomthreads.each { |t|
					t.join
				}
				MU.log "Setting min_size to #{@pool['min_size']} and max_size to #{@pool['max_size']}"
				MU.autoscale.update_auto_scaling_group(
					auto_scaling_group_name: pool_name,
					min_size: @pool['min_size'],
					max_size: @pool['max_size']
				)
			end
			MU.log "See /var/log/mu-momma-cat.log for asynchronous bootstrap progress.", MU::NOTICE

			return asg
		end
	end
end
